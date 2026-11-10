/**
 * ESP32 Wake-on-LAN via Tailscale
 * Tested board: ESP32-WROOM-32D dev kit (no PSRAM)
 * Port  : /dev/ttyUSB0
 *
 * The device joins your Tailscale network and listens on a
 * UDP port.  Any UDP packet arriving on that port triggers a WoL magic packet
 * broadcast on the local LAN, waking the configured PC.
 *
 * Trigger from any Tailscale peer:
 *   echo wake | nc -u <esp32-tailscale-ip> 9999 -w1
 *
 * Configure via:  idf.py menuconfig  →  "Wake-on-LAN Configuration"
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"

#include "ts.h"

static const char *TAG = "wol";

/* ============================================================================
 * WiFi
 * ========================================================================== */

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    static int retries = 0;

    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (retries < 20) {
            esp_wifi_connect();
            retries++;
            ESP_LOGW(TAG, "WiFi retry %d/20...", retries);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "WiFi connected: " IPSTR, IP2STR(&ev->ip_info.ip));
        retries = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid     = CONFIG_WOL_WIFI_SSID,
            .password = CONFIG_WOL_WIFI_PASSWORD,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "WiFi connection failed after 20 retries, restarting...");
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_restart();
    }
}

/* ============================================================================
 * Wake-on-LAN
 * ========================================================================== */

/**
 * Parse "AA:BB:CC:DD:EE:FF" into 6 bytes.  Returns true on success.
 */
static bool parse_mac(const char *str, uint8_t mac[6])
{
    int n = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    return n == 6;
}

/**
 * Build and broadcast a WoL magic packet on the local LAN.
 *
 * Uses a plain BSD socket (NOT the WireGuard/Tailscale interface).
 * The socket is bound to the WiFi STA IP to ensure it exits via WiFi, not VPN.
 *
 * Magic packet (102 bytes):
 *   6 × 0xFF  +  16 × <target MAC>
 */
static esp_err_t wol_send_magic_packet(const uint8_t mac[6])
{
    /* Build packet */
    uint8_t pkt[102];
    memset(pkt, 0xFF, 6);
    for (int i = 0; i < 16; i++) {
        memcpy(pkt + 6 + i * 6, mac, 6);
    }

    /* Open socket */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed: %d", errno);
        return ESP_FAIL;
    }

    /* Enable broadcast */
    int bcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

    /*
     * Bind to the WiFi STA IP so the packet exits via WiFi, not WireGuard.
     * Without this, lwIP might route the broadcast out the wrong interface
     * when the Tailscale VPN is active.
     */
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(sta, &ip_info) == ESP_OK) {
            struct sockaddr_in src = {
                .sin_family      = AF_INET,
                .sin_port        = htons(0),
                .sin_addr.s_addr = ip_info.ip.addr,   /* network byte order */
            };
            bind(sock, (struct sockaddr *)&src, sizeof(src));
        }
    }

    /* Send to configured broadcast address, port 9 (WoL standard) */
    struct sockaddr_in dest = {
        .sin_family      = AF_INET,
        .sin_port        = htons(9),
        .sin_addr.s_addr = inet_addr(CONFIG_WOL_BROADCAST_IP),
    };

    ssize_t sent = sendto(sock, pkt, sizeof(pkt), 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    close(sock);

    if (sent != (ssize_t)sizeof(pkt)) {
        ESP_LOGE(TAG, "sendto() sent %d/%d bytes (errno %d)",
                 (int)sent, (int)sizeof(pkt), errno);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Magic packet sent → %02X:%02X:%02X:%02X:%02X:%02X  (via %s:9)",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
             CONFIG_WOL_BROADCAST_IP);
    return ESP_OK;
}

/* ============================================================================
 * WoL Listener Task
 * ========================================================================== */

static void wol_task(void *arg)
{
    ts_t *ml = (ts_t *)arg;

    /* Validate MAC at startup — fail fast with a clear error */
    uint8_t target_mac[6];
    if (!parse_mac(CONFIG_WOL_TARGET_MAC, target_mac)) {
        ESP_LOGE(TAG, "----------------------------------------------------");
        ESP_LOGE(TAG, "  Invalid MAC address: '%s'", CONFIG_WOL_TARGET_MAC);
        ESP_LOGE(TAG, "  Run:  idf.py menuconfig");
        ESP_LOGE(TAG, "  →  Wake-on-LAN Configuration → Target PC MAC");
        ESP_LOGE(TAG, "  Format: AA:BB:CC:DD:EE:FF");
        ESP_LOGE(TAG, "----------------------------------------------------");
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Target MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             target_mac[0], target_mac[1], target_mac[2],
             target_mac[3], target_mac[4], target_mac[5]);

    /* Wait for Tailscale to come up */
    ESP_LOGI(TAG, "Waiting for Tailscale...");
    while (!ts_is_connected(ml)) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    char vpn_ip[16];
    ts_vpn_ip_to_str(ts_get_vpn_ip(ml), vpn_ip);

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔══════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║  ESP32 Wake-on-LAN  —  READY             ║");
    ESP_LOGI(TAG, "║                                          ║");
    ESP_LOGI(TAG, "║  Tailscale IP : %-26s║", vpn_ip);
    ESP_LOGI(TAG, "║  Listen port  : %-26d║", CONFIG_WOL_LISTEN_PORT);
    ESP_LOGI(TAG, "║                                          ║");
    ESP_LOGI(TAG, "║  Trigger (from any Tailscale peer):      ║");
    ESP_LOGI(TAG, "║  echo wake | nc -u %s %d -w1", vpn_ip, CONFIG_WOL_LISTEN_PORT);
    ESP_LOGI(TAG, "╚══════════════════════════════════════════╝");
    ESP_LOGI(TAG, "");

    ts_udp_socket_t *sock = NULL;
    bool prev_connected = true; /* already confirmed connected above */

    for (;;) {
        bool connected = ts_is_connected(ml);

        /*
         * Detect reconnection: coordination went down and came back up.
         * Refresh the socket so we get fresh WireGuard sessions and resend
         * CallMeMaybe to all peers.
         */
        if (connected && !prev_connected) {
            ESP_LOGI(TAG, "Tailscale reconnected — refreshing UDP socket");
            if (sock) {
                ts_udp_close(sock);
                sock = NULL;
            }
        }
        prev_connected = connected;

        /*
         * Create socket only when coordination is up (ts_udp_create
         * requires connected state to bind to the WireGuard netif).
         */
        if (connected && !sock) {
            sock = ts_udp_create(ml, CONFIG_WOL_LISTEN_PORT);
            if (!sock) {
                ESP_LOGE(TAG, "Failed to create UDP socket, retrying in 2 s...");
                vTaskDelay(pdMS_TO_TICKS(2000));
                continue;
            }
            ESP_LOGI(TAG, "UDP socket ready on Tailscale port %d", CONFIG_WOL_LISTEN_PORT);
        }

        /*
         * No socket yet (still waiting for first connection) — just wait.
         * NOTE: once created, we keep the socket alive even when coordination
         * reconnects.  The WireGuard netif is never torn down during a normal
         * coordination-only reconnect, so the lwIP UDP PCB keeps working and
         * can receive triggers via DERP throughout the ~23-second reconnect window.
         */
        if (!sock) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        /* Poll with a short timeout so we react to disconnections quickly */
        uint8_t buf[64];
        size_t  len = sizeof(buf);
        uint32_t src_ip;
        uint16_t src_port;

        esp_err_t err = ts_udp_recv(sock, &src_ip, &src_port,
                                           buf, &len, 500);
        if (err == ESP_OK) {
            char src_str[16];
            ESP_LOGI(TAG, "Trigger from %s:%d — firing WoL",
                     ts_vpn_ip_to_str(src_ip, src_str), src_port);
            if (wol_send_magic_packet(target_mac) == ESP_OK) {
                const char ack[] = "ok";
                ts_udp_send(sock, src_ip, src_port, ack, sizeof(ack) - 1);
                ESP_LOGI(TAG, "ACK sent to %s:%d", src_str, src_port);
            }

        } else if (err == ESP_ERR_TIMEOUT) {
            /* Normal — keep looping */

        } else {
            /* Unexpected error: socket gone stale */
            ESP_LOGW(TAG, "UDP recv error (%s), recreating socket...",
                     esp_err_to_name(err));
            ts_udp_close(sock);
            sock = NULL;
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
}

/* ============================================================================
 * Tailscale callbacks
 * ========================================================================== */

static void on_connected(void)
{
    ESP_LOGI(TAG, "*** Tailscale CONNECTED ***");
}

static void on_disconnected(void)
{
    ESP_LOGW(TAG, "Tailscale disconnected");
}

static void on_state_change(ts_state_t old_s, ts_state_t new_s)
{
    ESP_LOGI(TAG, "Tailscale state: %s → %s",
             ts_state_to_str(old_s),
             ts_state_to_str(new_s));
}

/* ============================================================================
 * app_main
 * ========================================================================== */

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32 Wake-on-LAN  (Tailscale lib %s)", TS_VERSION);
    ESP_LOGI(TAG, "Free heap at boot: %lu B",
             (unsigned long)esp_get_free_heap_size());

    /* NVS — required by WiFi driver */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* WiFi */
    ESP_LOGI(TAG, "Connecting to WiFi '%s'...", CONFIG_WOL_WIFI_SSID);
    wifi_init();
    ESP_LOGI(TAG, "Free heap after WiFi: %lu B",
             (unsigned long)esp_get_free_heap_size());

    /* Tailscale — memory-optimised for no-PSRAM ESP32 */
    ts_config_t cfg;
    ts_get_default_config(&cfg);

    cfg.auth_key            = CONFIG_WOL_TAILSCALE_AUTH_KEY;
    cfg.device_name         = CONFIG_WOL_DEVICE_NAME;
    cfg.enable_derp         = true;   /* Required for remote NAT traversal */
    cfg.enable_disco        = true;
    cfg.enable_stun         = true;
    cfg.max_peers           = 4;      /* Low value saves SRAM */
    cfg.on_connected        = on_connected;
    cfg.on_disconnected     = on_disconnected;
    cfg.on_state_change     = on_state_change;

    ts_t *ml = ts_init(&cfg);
    if (!ml) {
        ESP_LOGE(TAG, "Tailscale init failed — likely out of memory");
        ESP_LOGE(TAG, "Free heap: %lu B", (unsigned long)esp_get_free_heap_size());
        ESP_LOGE(TAG, "Try reducing CONFIG_TS_COORD_BUFFER_SIZE_KB to 16");
        return;
    }

    ESP_LOGI(TAG, "Free heap after Tailscale init: %lu B",
             (unsigned long)esp_get_free_heap_size());

    ESP_ERROR_CHECK(ts_connect(ml));

    /* WoL listener runs in its own task (4 KB stack is enough) */
    xTaskCreate(wol_task, "wol", 6144, ml, 5, NULL);

    /* Drive Tailscale state machine from main task */
    while (1) {
        ts_update(ml);
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}
