/**
 * @file ts_wireguard.c
 * @brief WireGuard wrapper using wireguard-lwip
 *
 * Integrates wireguard-lwip (smartalock/wireguard-lwip) for ESP32.
 * Provides manual peer management for Tailscale multi-peer support.
 */

#include "ts_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "mbedtls/base64.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>

// WireGuard-lwIP headers
#include "wireguardif.h"
#include "wireguard.h"
#include "x25519.h"  // For public key derivation

// lwIP headers
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/ip.h"
#include "lwip/err.h"
#include "lwip/mem.h"      // For mem_free()
#include "lwip/udp.h"      // For udp_remove()
#include "lwip/pbuf.h"     // For pbuf_alloc()
#include "lwip/tcpip.h"   // For tcpip_callback()

// External lwIP global
extern struct netif *netif_list;

static const char *TAG = "ts_wg";

/* Internal lifecycle API provided by the bundled wireguard_lwip fork.
 * Called exclusively in the lwIP TCP/IP thread via tcpip_callback(). */
extern err_t wireguardif_shutdown(struct netif *netif);


/* Forward declaration for DERP output callback */
static err_t wg_derp_output_callback(const uint8_t *peer_public_key, const uint8_t *data, size_t len, void *ctx);

/* ============================================================================
 * Deferred DERP Packet Queue
 *
 * When WireGuard's timer callback triggers a retransmission, it runs from
 * the lwIP tcpip thread which has insufficient stack for mbedtls TLS ops.
 * We queue these packets and send them from the main Tailscale task.
 * ========================================================================== */

#define DERP_QUEUE_SIZE 32
// A full WireGuard transport packet may be larger than a handshake (148 bytes).
// Cap total queued packet memory to protect the ESP32 without PSRAM.
#define DERP_QUEUE_MEMORY_LIMIT (8U * 1024U)
#define DERP_QUEUE_MAX_ATTEMPTS 6U
#define DERP_QUEUE_MAX_AGE_MS 30000U
#define DERP_QUEUE_RETRY_MS 300U

typedef struct {
    uint8_t peer_pubkey[32];
    uint8_t *data;  // Heap-owned until successfully sent or dropped.
    size_t len;
    bool pending;
    bool in_flight;
    uint8_t attempts;
    uint64_t queued_ms;
    uint64_t retry_after_ms;
} derp_queued_packet_t;

static derp_queued_packet_t derp_packet_queue[DERP_QUEUE_SIZE];
static ts_t *queued_ml_ctx = NULL;
static size_t queued_derp_bytes = 0;
static bool derp_queue_processing = false;
static portMUX_TYPE derp_queue_lock = portMUX_INITIALIZER_UNLOCKED;

/* NVS keys for persistent storage */
#define NVS_NAMESPACE       "tailscale"
#define NVS_KEY_WG_PRIVATE  "wg_private"
#define NVS_KEY_WG_PUBLIC   "wg_public"
#define NVS_KEY_DISCO_PRI   "disco_pri"
#define NVS_KEY_DISCO_PUB   "disco_pub"

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * @brief Generate WireGuard private/public key pair
 */
static void generate_wireguard_keys(uint8_t *private_key, uint8_t *public_key) {
    // Generate random private key
    esp_fill_random(private_key, 32);

    // Clamp private key (Curve25519 requirement)
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;

    // Derive public key from private key using Curve25519 base point multiplication
    x25519_base(public_key, private_key, 1);
}

/**
 * @brief Load or generate WireGuard and Disco keys from NVS
 *
 * Keys are persisted so the device identity remains stable across reboots.
 * This is critical for Tailscale - if keys change, peers see a "new" device.
 */
static esp_err_t load_or_generate_keys(ts_t *ml) {
    nvs_handle_t nvs;
    esp_err_t ret;
    bool need_save = false;

    ret = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for WireGuard identity: %s", esp_err_to_name(ret));
        return ret;  // Fail closed rather than silently changing device identity.
    }

    // Try to load WireGuard keys
    size_t key_len = 32;
    ret = nvs_get_blob(nvs, NVS_KEY_WG_PRIVATE, ml->wireguard.private_key, &key_len);
    if (ret == ESP_OK && key_len == 32) {
        key_len = 32;
        ret = nvs_get_blob(nvs, NVS_KEY_WG_PUBLIC, ml->wireguard.public_key, &key_len);
        if (ret == ESP_OK && key_len == 32) {
            uint8_t derived_public[32];
            x25519_base(derived_public, ml->wireguard.private_key, 1);
            if (memcmp(derived_public, ml->wireguard.public_key, 32) != 0) {
                memcpy(ml->wireguard.public_key, derived_public, 32);
                need_save = true;
            }
            ESP_LOGI(TAG, "Loaded existing WireGuard keys from NVS");
        } else {
            // Regenerate public key from private
            x25519_base(ml->wireguard.public_key, ml->wireguard.private_key, 1);
            need_save = true;
        }
    } else if (ret == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "No WireGuard keys in NVS, generating new ones");
        generate_wireguard_keys(ml->wireguard.private_key, ml->wireguard.public_key);
        need_save = true;
    } else {
        ESP_LOGE(TAG, "Failed to read WireGuard private key from NVS: %s", esp_err_to_name(ret));
        nvs_close(nvs);
        return ret == ESP_OK ? ESP_ERR_INVALID_SIZE : ret;
    }

    // Try to load Disco keys
    key_len = 32;
    ret = nvs_get_blob(nvs, NVS_KEY_DISCO_PRI, ml->wireguard.disco_private_key, &key_len);
    if (ret == ESP_OK && key_len == 32) {
        key_len = 32;
        ret = nvs_get_blob(nvs, NVS_KEY_DISCO_PUB, ml->wireguard.disco_public_key, &key_len);
        if (ret == ESP_OK && key_len == 32) {
            uint8_t derived_public[32];
            x25519_base(derived_public, ml->wireguard.disco_private_key, 1);
            if (memcmp(derived_public, ml->wireguard.disco_public_key, 32) != 0) {
                memcpy(ml->wireguard.disco_public_key, derived_public, 32);
                need_save = true;
            }
            ESP_LOGI(TAG, "Loaded existing Disco keys from NVS");
        } else {
            x25519_base(ml->wireguard.disco_public_key, ml->wireguard.disco_private_key, 1);
            need_save = true;
        }
    } else if (ret == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "No Disco keys in NVS, generating new ones");
        generate_wireguard_keys(ml->wireguard.disco_private_key, ml->wireguard.disco_public_key);
        need_save = true;
    } else {
        ESP_LOGE(TAG, "Failed to read Disco private key from NVS: %s", esp_err_to_name(ret));
        nvs_close(nvs);
        return ret == ESP_OK ? ESP_ERR_INVALID_SIZE : ret;
    }

    // Save newly generated keys
    if (need_save) {
        ret = nvs_set_blob(nvs, NVS_KEY_WG_PRIVATE, ml->wireguard.private_key, 32);
        if (ret == ESP_OK) {
            ret = nvs_set_blob(nvs, NVS_KEY_WG_PUBLIC, ml->wireguard.public_key, 32);
        }
        if (ret == ESP_OK) {
            ret = nvs_set_blob(nvs, NVS_KEY_DISCO_PRI, ml->wireguard.disco_private_key, 32);
        }
        if (ret == ESP_OK) {
            ret = nvs_set_blob(nvs, NVS_KEY_DISCO_PUB, ml->wireguard.disco_public_key, 32);
        }
        if (ret == ESP_OK) {
            ret = nvs_commit(nvs);
        }

        if (ret == ESP_OK) {
            ESP_LOGI(TAG, "Saved new WireGuard/Disco keys to NVS");
        } else {
            ESP_LOGW(TAG, "Failed to save keys to NVS: %d", ret);
        }
    }

    nvs_close(nvs);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "WireGuard key persistence failed: %s", esp_err_to_name(ret));
    }
    return ret;
}

/**
 * @brief Convert binary key to base64 string using mbedtls
 */
static esp_err_t key_to_base64(const uint8_t *key, char *base64_out, size_t out_len) {
    // Use mbedtls for standard-compliant base64 encoding
    size_t olen = 0;
    int ret = mbedtls_base64_encode((unsigned char *)base64_out, out_len, &olen, key, 32);

    if (ret != 0) {
        ESP_LOGE("ts_wg", "Base64 encode failed: %d", ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/**
 * @brief Convert Tailscale IP format to lwIP ip_addr_t
 */
static void ts_ip_to_lwip(uint32_t ml_ip, ip_addr_t *lwip_ip) {
    // Tailscale uses host byte order (0x6440000A = 100.64.0.10)
    // lwIP uses network byte order
    IP4_ADDR(&lwip_ip->u_addr.ip4,
             (ml_ip >> 24) & 0xFF,
             (ml_ip >> 16) & 0xFF,
             (ml_ip >> 8) & 0xFF,
             ml_ip & 0xFF);
    lwip_ip->type = IPADDR_TYPE_V4;
}

static bool ts_wireguard_peer_index(const ts_t *ml, uint32_t vpn_ip,
                                    uint8_t *peer_index)
{
    uint8_t peer_table_index = ts_peer_find_by_vpn_ip(ml, vpn_ip);
    if (peer_table_index == 0xFF || peer_table_index >= TS_MAX_PEERS) {
        return false;
    }
    *peer_index = ml->peer_wg_indices[peer_table_index];
    if (*peer_index == WIREGUARDIF_INVALID_INDEX) {
        return false;
    }
    return true;
}

/*
 * Synchronous cross-thread operations.  The stack context stays valid because
 * callers wait for the semaphore before returning.  Never call these wrappers
 * from lwIP's TCP/IP thread (that would deadlock).
 */
typedef struct {
    struct netif *netif;
    ts_t *ml;
    SemaphoreHandle_t done;
    struct wireguardif_init_data init_data;
    err_t result;
} ts_wg_lwip_op_t;

typedef enum {
    TS_WG_OP_ADD_PEER,
    TS_WG_OP_UPDATE_ENDPOINT,
    TS_WG_OP_CONNECT,
    TS_WG_OP_CONNECT_DERP,
    TS_WG_OP_PEER_IS_UP,
} ts_wg_peer_op_kind_t;

typedef struct {
    struct netif *netif;
    ts_wg_peer_op_kind_t kind;
    struct wireguardif_peer *peer;
    uint8_t peer_index;
    ip_addr_t *endpoint_ip;
    uint16_t endpoint_port;
    ip_addr_t *current_ip;
    u16_t *current_port;
    err_t result;
    SemaphoreHandle_t done;
} ts_wg_peer_op_t;

typedef struct {
    struct netif *netif;
    struct wireguard_device *device;
    struct udp_pcb *pcb;
    struct pbuf *p;
    uint32_t src_ip;
    uint16_t src_port;
    const uint8_t *data;
    size_t len;
    bool derp;
    err_t result;
    SemaphoreHandle_t done;
} ts_wg_rx_op_t;

typedef struct {
    struct netif *netif;
    uint32_t vpn_ip;
    err_t result;
    SemaphoreHandle_t done;
} ts_wg_ip_op_t;

extern void wireguardif_network_rx(void *arg, struct udp_pcb *pcb,
                                   struct pbuf *p, const ip_addr_t *addr,
                                   u16_t port);

static void ts_wg_rx_callback(void *argument)
{
    ts_wg_rx_op_t *op = argument;
    if (op->derp) {
        ip_addr_t src_addr;
        IP_ADDR4(&src_addr, 0, 0, 0, 0);
        wireguardif_network_rx(op->device, op->pcb, op->p, &src_addr, 41641);
        op->result = ERR_OK;
    } else {
        op->result = wireguardif_inject_packet(op->netif, op->src_ip,
                                               op->src_port, op->data, op->len);
    }
    xSemaphoreGive(op->done);
}

static void ts_wg_ip_callback(void *argument)
{
    ts_wg_ip_op_t *op = argument;
    ip4_addr_t ip4addr;
    IP4_ADDR(&ip4addr,
             (op->vpn_ip >> 24) & 0xFF,
             (op->vpn_ip >> 16) & 0xFF,
             (op->vpn_ip >> 8) & 0xFF,
             op->vpn_ip & 0xFF);
    ip4_addr_set(&op->netif->ip_addr.u_addr.ip4, &ip4addr);
    op->result = ERR_OK;
    xSemaphoreGive(op->done);
}

static void ts_wg_peer_callback(void *argument)
{
    ts_wg_peer_op_t *op = argument;
    switch (op->kind) {
        case TS_WG_OP_ADD_PEER:
            op->result = wireguardif_add_peer(op->netif, op->peer,
                                              &op->peer_index);
            break;
        case TS_WG_OP_UPDATE_ENDPOINT:
            op->result = wireguardif_update_endpoint(op->netif, op->peer_index,
                                                     op->endpoint_ip,
                                                     op->endpoint_port);
            break;
        case TS_WG_OP_CONNECT:
            op->result = wireguardif_connect(op->netif, op->peer_index);
            break;
        case TS_WG_OP_CONNECT_DERP:
            op->result = wireguardif_connect_derp(op->netif, op->peer_index);
            break;
        case TS_WG_OP_PEER_IS_UP:
            op->result = wireguardif_peer_is_up(op->netif, op->peer_index,
                                                op->current_ip,
                                                op->current_port);
            break;
    }
    xSemaphoreGive(op->done);
}

static err_t ts_wg_peer_call(ts_wg_peer_op_t *op)
{
    if (tcpip_callback(ts_wg_peer_callback, op) != ERR_OK) {
        return ERR_IF;
    }
    (void)xSemaphoreTake(op->done, portMAX_DELAY);
    return op->result;
}

static void ts_wg_lwip_init_callback(void *argument) {
    ts_wg_lwip_op_t *op = (ts_wg_lwip_op_t *)argument;
    struct netif *netif = op->netif;
    netif->state = &op->init_data;
    netif->input = ip_input;
    op->result = wireguardif_init(netif);
    if (op->result == ERR_OK) {
        /* Existing project manually registers its interface. Preserve that
         * behavior, but do the operation under TCP/IP thread ownership. */
        IP4_ADDR(&netif->ip_addr.u_addr.ip4, 100, 64, 0, 1);
        netif->ip_addr.type = IPADDR_TYPE_V4;
        IP4_ADDR(&netif->netmask.u_addr.ip4, 255, 192, 0, 0);
        netif->netmask.type = IPADDR_TYPE_V4;
        IP4_ADDR(&netif->gw.u_addr.ip4, 0, 0, 0, 0);
        netif->gw.type = IPADDR_TYPE_V4;

        netif->next = netif_list;
        netif_list = netif;
        netif_set_up(netif);
        netif_set_link_up(netif);
        wireguardif_set_derp_output(netif, wg_derp_output_callback, op->ml);
    }
    xSemaphoreGive(op->done);
}

static void ts_wg_lwip_shutdown_callback(void *argument) {
    ts_wg_lwip_op_t *op = (ts_wg_lwip_op_t *)argument;
    op->result = wireguardif_shutdown(op->netif);
    xSemaphoreGive(op->done);
}

/* ============================================================================
 * Initialization
 * ========================================================================== */

esp_err_t ts_wireguard_init(ts_t *ml) {
    ESP_LOGI(TAG, "Initializing WireGuard with wireguard-lwip");

    memset(&ml->wireguard, 0, sizeof(ts_wireguard_t));

    // Do not retain queue entries from a previous WireGuard session.
    // Initialization is called only after the previous connection task stops.
    uint8_t *stale_queue_data[DERP_QUEUE_SIZE] = {0};
    portENTER_CRITICAL(&derp_queue_lock);
    bool queue_busy = derp_queue_processing;
    if (!queue_busy) {
        for (int i = 0; i < DERP_QUEUE_SIZE; i++) {
            stale_queue_data[i] = derp_packet_queue[i].data;
            memset(&derp_packet_queue[i], 0, sizeof(derp_packet_queue[i]));
        }
        queued_derp_bytes = 0;
        queued_ml_ctx = NULL;
    }
    portEXIT_CRITICAL(&derp_queue_lock);
    if (queue_busy) {
        ESP_LOGE(TAG, "Cannot initialize WireGuard while DERP queue is draining");
        return ESP_ERR_INVALID_STATE;
    }
    for (int i = 0; i < DERP_QUEUE_SIZE; i++) {
        free(stale_queue_data[i]);
    }

    // Load or generate WireGuard and Disco keys (persisted in NVS)
    esp_err_t key_ret = load_or_generate_keys(ml);
    if (key_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load/generate keys: %d", key_ret);
        return key_ret;
    }

    // Convert private key to base64 for wireguard-lwip (store in persistent struct)
    esp_err_t b64_ret = key_to_base64(ml->wireguard.private_key, ml->wireguard.private_key_b64,
                                       sizeof(ml->wireguard.private_key_b64));
    if (b64_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to encode private key to base64");
        return b64_ret;
    }

    ESP_LOGI(TAG, "WireGuard and Disco keys ready");

    // Allocate lwIP netif structure
    // IMPORTANT: Use calloc() to zero-initialize all fields, including:
    // - netif->client_data[] array (ensures lwip_get_esp_netif() returns NULL)
    // - All callback function pointers (status_callback, link_callback, etc.)
    // This prevents ESP-IDF's callbacks from being triggered during manual netif setup
    ml->wireguard.netif = (struct netif *)calloc(1, sizeof(struct netif));
    if (!ml->wireguard.netif) {
        ESP_LOGE(TAG, "Failed to allocate netif");
        return ESP_ERR_NO_MEM;
    }

    /* The raw lwIP APIs and sys_timeout() in wireguardif_init() must be run
     * by lwIP's TCP/IP thread.  This callback completes before we return. */
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (done == NULL) {
        free(ml->wireguard.netif);
        ml->wireguard.netif = NULL;
        return ESP_ERR_NO_MEM;
    }

    ts_wg_lwip_op_t op = {
        .netif = (struct netif *)ml->wireguard.netif,
        .ml = ml,
        .done = done,
        .result = ERR_IF,
        .init_data = {
            .private_key = ml->wireguard.private_key_b64,
            .listen_port = 51820,
            .bind_netif = NULL,
        },
    };
    err_t call_err = tcpip_callback(ts_wg_lwip_init_callback, &op);
    if (call_err != ERR_OK) {
        ESP_LOGE(TAG, "Failed to schedule WireGuard initialization in TCP/IP thread: %d", call_err);
        vSemaphoreDelete(done);
        free(ml->wireguard.netif);
        ml->wireguard.netif = NULL;
        return ESP_FAIL;
    }

    /* Do not timeout and release 'op' while its callback may still execute. */
    (void)xSemaphoreTake(done, portMAX_DELAY);
    vSemaphoreDelete(done);
    if (op.result != ERR_OK) {
        ESP_LOGE(TAG, "WireGuard lwIP initialization failed: %d", op.result);
        free(ml->wireguard.netif);
        ml->wireguard.netif = NULL;
        return ESP_FAIL;
    }

    ml->wireguard.listen_port = 51820;
    ml->wireguard.initialized = true;
    ESP_LOGI(TAG, "WireGuard interface initialized on port %d", ml->wireguard.listen_port);

    return ESP_OK;
}

esp_err_t ts_wireguard_deinit(ts_t *ml) {
    if (ml == NULL) return ESP_ERR_INVALID_ARG;
    if (!ml->wireguard.initialized) return ESP_OK;
    if (ml->wireguard.netif == NULL) return ESP_ERR_INVALID_STATE;

    ESP_LOGI(TAG, "Deinitializing WireGuard in lwIP TCP/IP thread");
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (done == NULL) return ESP_ERR_NO_MEM;

    ts_wg_lwip_op_t op = {
        .netif = (struct netif *)ml->wireguard.netif,
        .done = done,
        .result = ERR_IF,
    };
    err_t call_err = tcpip_callback(ts_wg_lwip_shutdown_callback, &op);
    if (call_err != ERR_OK) {
        ESP_LOGE(TAG, "Failed to schedule WireGuard shutdown in TCP/IP thread: %d", call_err);
        vSemaphoreDelete(done);
        return ESP_FAIL;  // Keep device/netif allocated: callback timer may still refer to it.
    }

    /* Wait until the timer is cancelled and netif/device are removed. */
    (void)xSemaphoreTake(done, portMAX_DELAY);
    vSemaphoreDelete(done);
    if (op.result != ERR_OK) {
        ESP_LOGE(TAG, "WireGuard shutdown failed: %d", op.result);
        return ESP_FAIL;  // Never free the netif while its timer may remain active.
    }

    free(ml->wireguard.netif); // Our calloc(); device was freed inside TCP/IP callback.
    ml->wireguard.netif = NULL;
    ml->wireguard.initialized = false;
    memset(&ml->wireguard, 0, sizeof(ts_wireguard_t));
    return ESP_OK;
}

/* ============================================================================
 * Peer Management
 * ========================================================================== */

esp_err_t ts_wireguard_add_peer(ts_t *ml, const ts_peer_t *peer) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Adding WireGuard peer: %s", peer->hostname);

    // Convert peer public key to base64
    char peer_pubkey_b64[64];
    esp_err_t peer_b64_ret = key_to_base64(peer->public_key, peer_pubkey_b64, sizeof(peer_pubkey_b64));
    if (peer_b64_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to encode peer public key to base64");
        return peer_b64_ret;
    }

    // Initialize peer structure
    struct wireguardif_peer wg_peer;
    wireguardif_peer_init(&wg_peer);

    wg_peer.public_key = peer_pubkey_b64;
    wg_peer.preshared_key = NULL;  // No PSK for now

    // Set allowed IP to the peer's SPECIFIC VPN IP with /32 mask
    // This is critical for multi-peer routing - each peer gets only their own VPN IP
    // so that peer_lookup_by_allowed_ip() returns the correct peer for TX routing.
    //
    // Note: Standard WireGuard Tailscale configs use 100.64.0.0/10, but that's for
    // a SINGLE peer scenario. With multiple peers, we need /32 per peer.
    uint8_t ip_b1 = (peer->vpn_ip >> 24) & 0xFF;
    uint8_t ip_b2 = (peer->vpn_ip >> 16) & 0xFF;
    uint8_t ip_b3 = (peer->vpn_ip >> 8) & 0xFF;
    uint8_t ip_b4 = peer->vpn_ip & 0xFF;

    IP4_ADDR(&wg_peer.allowed_ip.u_addr.ip4, ip_b1, ip_b2, ip_b3, ip_b4);
    wg_peer.allowed_ip.type = IPADDR_TYPE_V4;
    IP4_ADDR(&wg_peer.allowed_mask.u_addr.ip4, 255, 255, 255, 255);  // /32 - single host
    wg_peer.allowed_mask.type = IPADDR_TYPE_V4;

    ESP_LOGI(TAG, "Peer allowed IP: %u.%u.%u.%u/32", ip_b1, ip_b2, ip_b3, ip_b4);

    // Set endpoint if available (IPv4 only for now - TODO: add IPv6 WireGuard support)
    if (peer->endpoint_count > 0 && !peer->endpoints[0].is_derp && !peer->endpoints[0].is_ipv6) {
        ts_ip_to_lwip(peer->endpoints[0].addr.ip4, &wg_peer.endpoint_ip);
        wg_peer.endport_port = peer->endpoints[0].port;
    } else {
        // No direct endpoint or IPv6-only, will rely on DERP
        memset(&wg_peer.endpoint_ip, 0, sizeof(ip_addr_t));
        wg_peer.endport_port = 0;
    }

    // Set keepalive (25 seconds for NAT traversal)
    wg_peer.keep_alive = 25;

    // Add peer to WireGuard interface
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    ts_wg_peer_op_t peer_op = {
        .netif = (struct netif *)ml->wireguard.netif,
        .kind = TS_WG_OP_ADD_PEER,
        .peer = &wg_peer,
        .peer_index = WIREGUARDIF_INVALID_INDEX,
        .done = done,
        .result = ERR_IF,
    };
    err_t err = ts_wg_peer_call(&peer_op);
    u8_t peer_index = peer_op.peer_index;
    vSemaphoreDelete(done);

    if (err != ERR_OK) {
        ESP_LOGE(TAG, "Failed to add peer: lwIP error %d", err);
        return ESP_FAIL;
    }

    // Store peer index for later reference
    uint8_t peer_table_index = (uint8_t)(peer - ml->peers);
    if (peer_table_index >= TS_MAX_PEERS) {
        ESP_LOGE(TAG, "Peer table index is invalid");
        return ESP_FAIL;
    }
    ml->peer_wg_indices[peer_table_index] = peer_index;

    ESP_LOGI(TAG, "Peer added successfully (index %d)", peer_index);

    // Initiate handshake via DERP first (always reliable, bypasses NAT issues)
    // Direct UDP path will be tried later as an optimization via DISCO
    //
    // Why DERP-first:
    // - Direct UDP handshakes fail ~50-70% due to asymmetric NAT
    // - DERP uses TCP to Tailscale relay servers, always works
    // - Once handshake completes via DERP, traffic flows immediately
    // - DISCO will upgrade to direct path in background if possible
    ESP_LOGI(TAG, "Initiating handshake via DERP (reliable, bypasses NAT)");
    done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    peer_op.kind = TS_WG_OP_CONNECT_DERP;
    peer_op.peer_index = peer_index;
    peer_op.done = done;
    err = ts_wg_peer_call(&peer_op);
    vSemaphoreDelete(done);
    if (err != ERR_OK) {
        ESP_LOGW(TAG, "Failed to initiate DERP handshake: lwIP error %d", err);

        // Fallback: try direct if DERP fails and we have an endpoint
        if (peer->endpoint_count > 0 && !peer->endpoints[0].is_derp) {
            ESP_LOGI(TAG, "DERP failed, trying direct handshake as fallback");
            done = xSemaphoreCreateBinary();
            if (!done) return ESP_ERR_NO_MEM;
            peer_op.kind = TS_WG_OP_CONNECT;
            peer_op.done = done;
            err = ts_wg_peer_call(&peer_op);
            vSemaphoreDelete(done);
            if (err == ERR_OK) {
                uint32_t ip = ntohl(peer->endpoints[0].addr.ip4);
                ESP_LOGI(TAG, "Direct handshake initiated to %lu.%lu.%lu.%lu:%u",
                         (unsigned long)((ip >> 24) & 0xFF),
                         (unsigned long)((ip >> 16) & 0xFF),
                         (unsigned long)((ip >> 8) & 0xFF),
                         (unsigned long)(ip & 0xFF),
                         peer->endpoints[0].port);
            }
        }
    } else {
        ESP_LOGI(TAG, "DERP handshake initiated for peer %s", peer->hostname);
    }

    return ESP_OK;
}

/**
 * @brief Update peer endpoint and initiate handshake
 *
 * Called when DISCO discovers a direct path to a peer.
 * Updates the WireGuard peer's endpoint and initiates handshake.
 */
esp_err_t ts_wireguard_update_endpoint(ts_t *ml, uint32_t vpn_ip,
                                               uint32_t endpoint_ip, uint16_t endpoint_port) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    // Find peer index by VPN IP
    uint8_t peer_index;
    if (!ts_wireguard_peer_index(ml, vpn_ip, &peer_index)) {
        return ESP_ERR_NOT_FOUND;
    }

    // Convert endpoint IP to lwIP format
    ip_addr_t lwip_endpoint;
    ts_ip_to_lwip(endpoint_ip, &lwip_endpoint);

    // Update peer endpoint
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    ts_wg_peer_op_t peer_op = {
        .netif = (struct netif *)ml->wireguard.netif,
        .kind = TS_WG_OP_UPDATE_ENDPOINT,
        .peer_index = peer_index,
        .endpoint_ip = &lwip_endpoint,
        .endpoint_port = endpoint_port,
        .done = done,
        .result = ERR_IF,
    };
    err_t err = ts_wg_peer_call(&peer_op);
    vSemaphoreDelete(done);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "Failed to update endpoint: lwIP error %d", err);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Updated peer endpoint to %u.%u.%u.%u:%u",
             (endpoint_ip >> 24) & 0xFF,
             (endpoint_ip >> 16) & 0xFF,
             (endpoint_ip >> 8) & 0xFF,
             endpoint_ip & 0xFF,
             endpoint_port);

    // Now initiate handshake with the new endpoint
    done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    peer_op.kind = TS_WG_OP_CONNECT;
    peer_op.done = done;
    err = ts_wg_peer_call(&peer_op);
    vSemaphoreDelete(done);
    if (err != ERR_OK) {
        ESP_LOGW(TAG, "Failed to initiate handshake after endpoint update: %d", err);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Handshake initiated with updated endpoint");
    return ESP_OK;
}

/**
 * @brief Trigger WireGuard handshake to a peer
 *
 * Used when attempting to send data to a peer that doesn't have an active session.
 * Initiates handshake via DERP (reliable) first, with direct UDP as fallback.
 *
 * @param ml Tailscale handle
 * @param vpn_ip Peer VPN IP (host byte order)
 * @return ESP_OK on success
 */
esp_err_t ts_wireguard_trigger_handshake(ts_t *ml, uint32_t vpn_ip) {
    if (!ml || !ml->wireguard.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    // Find peer index
    uint8_t peer_index;
    if (!ts_wireguard_peer_index(ml, vpn_ip, &peer_index)) {
        ESP_LOGW(TAG, "Peer not found for VPN IP: %lu.%lu.%lu.%lu",
                 (unsigned long)((vpn_ip >> 24) & 0xFF),
                 (unsigned long)((vpn_ip >> 16) & 0xFF),
                 (unsigned long)((vpn_ip >> 8) & 0xFF),
                 (unsigned long)(vpn_ip & 0xFF));
        return ESP_ERR_NOT_FOUND;
    }

    // Check if peer already has a valid session - if so, don't destroy it by initiating new handshake!
    ip_addr_t current_ip;
    memset(&current_ip, 0, sizeof(current_ip));
    u16_t current_port = 0;
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    ts_wg_peer_op_t peer_op = {
        .netif = (struct netif *)ml->wireguard.netif,
        .kind = TS_WG_OP_PEER_IS_UP,
        .peer_index = peer_index,
        .current_ip = &current_ip,
        .current_port = &current_port,
        .done = done,
        .result = ERR_IF,
    };
    err_t status = ts_wg_peer_call(&peer_op);
    vSemaphoreDelete(done);

    if (status == ERR_OK) {
        // Peer already has a valid keypair! Don't destroy it by initiating a new handshake.
        // The ERR_CONN from send might be because we're the responder and waiting for first RX.
        // Just return OK - the session exists, let it work.
        ESP_LOGI(TAG, "Peer %lu.%lu.%lu.%lu already has valid session, skipping handshake",
                 (unsigned long)((vpn_ip >> 24) & 0xFF),
                 (unsigned long)((vpn_ip >> 16) & 0xFF),
                 (unsigned long)((vpn_ip >> 8) & 0xFF),
                 (unsigned long)(vpn_ip & 0xFF));
        return ESP_OK;
    }

    if (status != ERR_CONN) {
        ESP_LOGW(TAG, "Cannot inspect WireGuard peer %lu.%lu.%lu.%lu: lwIP error %d",
                 (unsigned long)((vpn_ip >> 24) & 0xFF),
                 (unsigned long)((vpn_ip >> 16) & 0xFF),
                 (unsigned long)((vpn_ip >> 8) & 0xFF),
                 (unsigned long)(vpn_ip & 0xFF), status);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Triggering WireGuard handshake to peer %lu.%lu.%lu.%lu (index=%d)",
             (unsigned long)((vpn_ip >> 24) & 0xFF),
             (unsigned long)((vpn_ip >> 16) & 0xFF),
             (unsigned long)((vpn_ip >> 8) & 0xFF),
             (unsigned long)(vpn_ip & 0xFF),
             peer_index);

    // If peer has a non-zero endpoint, try direct connect first
    if (!ip_addr_isany(&current_ip) && current_port != 0) {
        ESP_LOGI(TAG, "Peer has direct endpoint, using wireguardif_connect");
        done = xSemaphoreCreateBinary();
        if (!done) return ESP_ERR_NO_MEM;
        peer_op.kind = TS_WG_OP_CONNECT;
        peer_op.done = done;
        err_t err = ts_wg_peer_call(&peer_op);
        vSemaphoreDelete(done);
        if (err == ERR_OK) {
            ESP_LOGI(TAG, "Direct handshake initiated");
            return ESP_OK;
        }
    }

    // No direct endpoint or direct failed - use DERP
    done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    peer_op.kind = TS_WG_OP_CONNECT_DERP;
    peer_op.done = done;
    err_t err = ts_wg_peer_call(&peer_op);
    vSemaphoreDelete(done);
    if (err == ERR_OK) {
        ESP_LOGI(TAG, "DERP handshake initiated");
        return ESP_OK;
    }

    // Fallback to direct if DERP also failed
    done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    peer_op.kind = TS_WG_OP_CONNECT;
    peer_op.done = done;
    err = ts_wg_peer_call(&peer_op);
    vSemaphoreDelete(done);
    if (err == ERR_OK) {
        ESP_LOGI(TAG, "Direct handshake initiated (fallback)");
        return ESP_OK;
    }

    ESP_LOGW(TAG, "Failed to trigger handshake: lwIP error %d", err);
    return ESP_FAIL;
}

/* ============================================================================
 * Data Transfer
 * ========================================================================== */

esp_err_t ts_wireguard_send(ts_t *ml, uint32_t dest_vpn_ip,
                                   const uint8_t *data, size_t len) {
    if (!ml->wireguard.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    // Find peer index
    uint8_t peer_index;
    if (!ts_wireguard_peer_index(ml, dest_vpn_ip, &peer_index)) {
        return ESP_ERR_NOT_FOUND;
    }

    // Check if peer is up
    ip_addr_t peer_ip;
    u16_t peer_port;
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    ts_wg_peer_op_t peer_op = {
        .netif = (struct netif *)ml->wireguard.netif,
        .kind = TS_WG_OP_PEER_IS_UP,
        .peer_index = peer_index,
        .current_ip = &peer_ip,
        .current_port = &peer_port,
        .done = done,
        .result = ERR_IF,
    };
    err_t err = ts_wg_peer_call(&peer_op);
    vSemaphoreDelete(done);

    if (err != ERR_OK) {
        ESP_LOGD(TAG, "Peer not ready, handshake may be in progress");
        return ESP_ERR_INVALID_STATE;
    }

    // TODO: Actually send data through WireGuard interface
    // For now, wireguard-lwip handles this at the lwIP layer automatically
    // We would need to create IP packets and pass them to the netif

    ESP_LOGD(TAG, "WireGuard send: %u bytes to peer %d", (unsigned int)len, peer_index);
    ml->stats.direct_packets_sent++;

    // Return success - actual sending happens via lwIP routing
    return ESP_OK;
}

esp_err_t ts_wireguard_receive(ts_t *ml) {
    if (!ml->wireguard.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    // Direct UDP reception is handled automatically by wireguard-lwip via udp_recv callback
    // This function processes DERP-relayed packets from the rx_queue
    while (ml->rx_head != ml->rx_tail) {
        ts_packet_t *pkt = &ml->rx_queue[ml->rx_tail];

        // Inject DERP-relayed packet into WireGuard
        esp_err_t ret = ts_wireguard_inject_derp_packet(ml, pkt->src_vpn_ip,
                                                                pkt->data, pkt->len);
        if (ret != ESP_OK) {
            ESP_LOGD(TAG, "Failed to inject DERP packet: %d", ret);
        }

        ml->rx_tail = (ml->rx_tail + 1) % TS_RX_QUEUE_SIZE;
    }

    return ESP_OK;
}

/**
 * @brief Inject a WireGuard packet for processing
 *
 * When a WireGuard packet arrives via DERP relay OR direct UDP (on DISCO port),
 * we need to pass it to the WireGuard stack for decryption and routing.
 *
 * @param ml Tailscale handle
 * @param src_ip Source IP in network byte order (0 for DERP relay)
 * @param data Raw WireGuard packet data
 * @param len Packet length
 * @return ESP_OK on success
 */
esp_err_t ts_wireguard_inject_derp_packet(ts_t *ml, uint32_t src_ip,
                                                  const uint8_t *data, size_t len) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    // lwIP pbuf_alloc accepts a 16-bit length. Never truncate size_t.
    if (!data || len < 4 || len > UINT16_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }

    struct netif *netif = (struct netif *)ml->wireguard.netif;
    struct wireguard_device *device = (struct wireguard_device *)netif->state;

    if (!device) {
        return ESP_ERR_INVALID_STATE;
    }

    // Create a pbuf to hold the packet
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) {
        ESP_LOGW(TAG, "Failed to allocate pbuf for WG packet");
        return ESP_ERR_NO_MEM;
    }

    // pbuf_take also works correctly if lwIP returns a chained pbuf.
    if (pbuf_take(p, data, (u16_t)len) != ERR_OK) {
        pbuf_free(p);
        return ESP_FAIL;
    }

    // Always inject DERP packets with src_addr = 0.0.0.0.
    //
    // Bug fixed: previously we passed the peer's VPN IP (e.g. 100.112.151.63) as
    // src_addr.  wireguard-lwip's update_peer_addr() then stored that as peer->ip,
    // causing wireguardif_peer_output() to skip the DERP relay callback and try a
    // direct udp_sendto() to the VPN IP (which is byte-swapped on the little-endian
    // ESP32 and completely unreachable).  The HANDSHAKE_RESPONSE was silently lost
    // every time, so the WireGuard session never completed.
    //
    // With 0.0.0.0, update_peer_addr() skips the update (it guards against any()),
    // peer->ip stays 0.0.0.0 (as set by wireguardif_connect_derp()), and
    // wireguardif_peer_output() correctly routes all responses through DERP.
    ESP_LOGD(TAG, "Injecting DERP WG packet (src_vpn_ip=0x%08lx kept internal)", (unsigned long)src_ip);

    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) {
        pbuf_free(p);
        return ESP_ERR_NO_MEM;
    }
    ts_wg_rx_op_t rx_op = {
        .netif = netif,
        .device = device,
        .pcb = device->udp_pcb,
        .p = p,
        .derp = true,
        .done = done,
        .result = ERR_IF,
    };
    if (tcpip_callback(ts_wg_rx_callback, &rx_op) != ERR_OK) {
        vSemaphoreDelete(done);
        pbuf_free(p);
        return ESP_FAIL;
    }
    (void)xSemaphoreTake(done, portMAX_DELAY);
    vSemaphoreDelete(done);

    return rx_op.result == ERR_OK ? ESP_OK : ESP_FAIL;
}

esp_err_t ts_wireguard_inject_packet(ts_t *ml, uint32_t src_ip, uint16_t src_port,
                                             const uint8_t *data, size_t len) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    struct netif *netif = (struct netif *)ml->wireguard.netif;

    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    ts_wg_rx_op_t rx_op = {
        .netif = netif,
        .src_ip = src_ip,
        .src_port = src_port,
        .data = data,
        .len = len,
        .done = done,
        .result = ERR_IF,
    };
    if (tcpip_callback(ts_wg_rx_callback, &rx_op) != ERR_OK) {
        vSemaphoreDelete(done);
        return ESP_FAIL;
    }
    (void)xSemaphoreTake(done, portMAX_DELAY);
    vSemaphoreDelete(done);
    err_t err = rx_op.result;

    if (err != ERR_OK) {
        ESP_LOGW(TAG, "wireguardif_inject_packet failed: %d", err);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/* ============================================================================
 * DERP Output Callback for WireGuard
 * ========================================================================== */

/**
 * @brief Callback invoked by WireGuard when it needs to send a packet to a peer
 *        that has no direct IP endpoint (DERP-only peer).
 *
 * This is called from wireguardif_peer_output() when peer->ip is 0.0.0.0.
 * We relay the WireGuard packet through DERP using the peer's public key.
 */
static err_t wg_derp_output_callback(const uint8_t *peer_public_key,
                                     const uint8_t *data, size_t len, void *ctx) {
    ts_t *ml = (ts_t *)ctx;
    if (!ml || !peer_public_key || !data || len == 0 || len > TS_NETWORK_BUFFER_SIZE) {
        return ERR_ARG;
    }

    // WireGuard invokes this callback from different task contexts, including
    // lwIP timers. Never do TLS I/O here; enqueue and return promptly.
    uint8_t *copy = malloc(len);
    if (!copy) return ERR_MEM;
    memcpy(copy, data, len);

    uint64_t now = ts_get_time_ms();
    int free_slot = -1;
    bool duplicate = false;
    bool accepted = false;
    portENTER_CRITICAL(&derp_queue_lock);
    if (queued_ml_ctx && queued_ml_ctx != ml) {
        // Avoid mixing packets from unrelated sessions.
        portEXIT_CRITICAL(&derp_queue_lock);
        free(copy);
        return ERR_IF;
    }
    for (int i = 0; i < DERP_QUEUE_SIZE; i++) {
        derp_queued_packet_t *slot = &derp_packet_queue[i];
        if (slot->pending && slot->len == len &&
            memcmp(slot->peer_pubkey, peer_public_key, 32) == 0 &&
            memcmp(slot->data, data, len) == 0) {
            duplicate = true;
            break;
        }
        if (!slot->pending && free_slot < 0) free_slot = i;
    }

    if (!duplicate && free_slot >= 0 &&
        len <= DERP_QUEUE_MEMORY_LIMIT - queued_derp_bytes) {
        derp_queued_packet_t *slot = &derp_packet_queue[free_slot];
        memcpy(slot->peer_pubkey, peer_public_key, 32);
        slot->data = copy;
        slot->len = len;
        slot->pending = true;
        slot->in_flight = false;
        slot->attempts = 0;
        slot->queued_ms = now;
        slot->retry_after_ms = now;
        queued_derp_bytes += len;
        queued_ml_ctx = ml;
        copy = NULL; // Ownership transferred to queue.
        accepted = true;
    }
    portEXIT_CRITICAL(&derp_queue_lock);

    free(copy);
    if (duplicate) return ERR_OK;
    if (!accepted) {
        ESP_LOGW(TAG, "DERP queue full or memory budget reached (packet=%u bytes)",
                 (unsigned)len);
        return ERR_MEM;
    }
    return ERR_OK;
}

/**
 * Drain at most one packet per call. TLS can block; retries are bounded.
 * A single processor may send, while lwIP timer callbacks continue enqueuing.
 */
void ts_wireguard_process_derp_queue(void) {
    int chosen = -1;
    ts_t *ml = NULL;
    uint64_t now = ts_get_time_ms();

    portENTER_CRITICAL(&derp_queue_lock);
    if (!derp_queue_processing && queued_ml_ctx) {
        for (int i = 0; i < DERP_QUEUE_SIZE; i++) {
            derp_queued_packet_t *slot = &derp_packet_queue[i];
            if (slot->pending && !slot->in_flight && now >= slot->retry_after_ms) {
                chosen = i;
                slot->in_flight = true;
                derp_queue_processing = true;
                ml = queued_ml_ctx;
                break;
            }
        }
    }
    portEXIT_CRITICAL(&derp_queue_lock);
    if (chosen < 0) return;

    // Queue entry remains allocated and reserved during this network call.
    derp_queued_packet_t *slot = &derp_packet_queue[chosen];
    esp_err_t err = ts_derp_send_raw(ml, slot->peer_pubkey, slot->data, slot->len);
    uint8_t *release_data = NULL;
    bool dropped = false;
    uint8_t attempts = 0;
    now = ts_get_time_ms();

    portENTER_CRITICAL(&derp_queue_lock);
    slot->in_flight = false;
    if (err == ESP_OK || ++slot->attempts >= DERP_QUEUE_MAX_ATTEMPTS ||
        now - slot->queued_ms >= DERP_QUEUE_MAX_AGE_MS) {
        dropped = (err != ESP_OK);
        release_data = slot->data;
        queued_derp_bytes -= slot->len;
        memset(slot, 0, sizeof(*slot));
    } else {
        // Backoff reduces contention with TLS reads and avoids a retry storm.
        slot->retry_after_ms = now + DERP_QUEUE_RETRY_MS * (1U << (slot->attempts - 1U));
        attempts = slot->attempts;
    }
    derp_queue_processing = false;
    portEXIT_CRITICAL(&derp_queue_lock);

    free(release_data);
    if (err != ESP_OK) {
        if (dropped) {
            ESP_LOGW(TAG, "DERP packet dropped after retry/age limit (error=%s)",
                     esp_err_to_name(err));
        } else {
            ESP_LOGD(TAG, "DERP queued send deferred (error=%s, attempts=%u)",
                     esp_err_to_name(err), attempts);
        }
    }
}

/* ============================================================================
 * Status & Utilities
 * ========================================================================== */

void ts_wireguard_get_public_key(const ts_t *ml, uint8_t *public_key) {
    // TODO: Extract actual public key from wireguard-lwip
    // For now, return the stored key
    memcpy(public_key, ml->wireguard.public_key, 32);
}

esp_err_t ts_wireguard_set_vpn_ip(ts_t *ml, uint32_t vpn_ip) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    // Skip if VPN IP is 0 (not assigned yet)
    if (vpn_ip == 0) {
        ESP_LOGW(TAG, "VPN IP not assigned yet, skipping netif update");
        return ESP_OK;
    }

    struct netif *netif = (struct netif *)ml->wireguard.netif;

    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) return ESP_ERR_NO_MEM;
    ts_wg_ip_op_t ip_op = {
        .netif = netif,
        .vpn_ip = vpn_ip,
        .result = ERR_IF,
        .done = done,
    };
    if (tcpip_callback(ts_wg_ip_callback, &ip_op) != ERR_OK) {
        vSemaphoreDelete(done);
        return ESP_FAIL;
    }
    (void)xSemaphoreTake(done, portMAX_DELAY);
    vSemaphoreDelete(done);
    if (ip_op.result != ERR_OK) {
        return ESP_FAIL;
    }

    ml->vpn_ip = vpn_ip;

    char ip_buf[16];
    ESP_LOGI(TAG, "WireGuard VPN IP set to: %s",
             ts_vpn_ip_to_str(vpn_ip, ip_buf));

    return ESP_OK;
}

/* ============================================================================
 * Magicsock Mode - WireGuard uses DISCO socket for all UDP I/O
 * ========================================================================== */

// Socket fd for magicsock mode (DISCO socket shared with WireGuard)
static int magicsock_fd = -1;
static SemaphoreHandle_t magicsock_mutex = NULL;

/**
 * @brief UDP output callback for magicsock mode
 *
 * Called by wireguard-lwip when it needs to send a UDP packet.
 * We send via the DISCO socket instead of WireGuard's internal socket.
 *
 * NOTE: This can be called from multiple contexts (timer callbacks, RX processing,
 * main task) so we use a mutex to serialize sendto calls.
 */
static err_t magicsock_udp_output(uint32_t dest_ip, uint16_t dest_port,
                                   const uint8_t *data, size_t len, void *ctx) {
    if (magicsock_fd < 0) {
        ESP_LOGE(TAG, "[MAGICSOCK] No socket configured");
        return ERR_IF;
    }

    // Take mutex with short timeout to prevent deadlock
    if (magicsock_mutex && xSemaphoreTake(magicsock_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        ESP_LOGW(TAG, "[MAGICSOCK] Mutex timeout, skipping TX (%u bytes)", (unsigned)len);
        return ERR_WOULDBLOCK;
    }

    err_t result = ERR_OK;

    // Use select() to check if socket is writable with timeout
    // This prevents sendto from blocking indefinitely
    fd_set write_fds;
    struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 };  // 10ms timeout
    FD_ZERO(&write_fds);
    FD_SET(magicsock_fd, &write_fds);

    int sel_ret = select(magicsock_fd + 1, NULL, &write_fds, NULL, &tv);
    if (sel_ret <= 0) {
        ESP_LOGW(TAG, "[MAGICSOCK] Socket not writable (select=%d)", sel_ret);
        result = ERR_WOULDBLOCK;
        goto done;
    }

    // dest_ip is in network byte order from wireguard-lwip
    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(dest_port),
        .sin_addr.s_addr = dest_ip
    };

    ssize_t sent = sendto(magicsock_fd, data, len, MSG_DONTWAIT,
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (sent < 0) {
        int err = errno;
        ESP_LOGW(TAG, "[MAGICSOCK] sendto failed: errno=%d (%s)", err, strerror(err));
        result = ERR_IF;
    } else {
        ESP_LOGD(TAG, "[MAGICSOCK] sent %d bytes to %d.%d.%d.%d:%u",
                 (int)sent,
                 (int)(dest_ip & 0xFF), (int)((dest_ip >> 8) & 0xFF),
                 (int)((dest_ip >> 16) & 0xFF), (int)((dest_ip >> 24) & 0xFF),
                 dest_port);
    }

done:
    if (magicsock_mutex) {
        xSemaphoreGive(magicsock_mutex);
    }

    return result;
}

esp_err_t ts_wireguard_enable_magicsock(ts_t *ml) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        ESP_LOGE(TAG, "WireGuard not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    // Create mutex for thread-safe sendto calls
    if (!magicsock_mutex) {
        magicsock_mutex = xSemaphoreCreateMutex();
        if (!magicsock_mutex) {
            ESP_LOGE(TAG, "Failed to create magicsock mutex");
            return ESP_ERR_NO_MEM;
        }
    }

    // Get the DISCO socket fd
    magicsock_fd = ts_disco_get_socket();
    if (magicsock_fd < 0) {
        ESP_LOGE(TAG, "DISCO socket not available");
        return ESP_ERR_INVALID_STATE;
    }

    // Register UDP output callback with wireguard-lwip
    struct netif *netif = (struct netif *)ml->wireguard.netif;
    wireguardif_set_udp_output(netif, magicsock_udp_output, ml);

    ESP_LOGI(TAG, "Magicsock enabled: WireGuard using DISCO socket fd=%d", magicsock_fd);

    return ESP_OK;
}
