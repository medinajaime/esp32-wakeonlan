/**
 * @file tailscale.c
 * @brief Tailscale main implementation
 */

#include "ts.h"
#include "ts_internal.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_mac.h"

static const char *TAG = "tailscale";

/* Static buffer for auto-generated device name */
static char s_device_name[20] = {0};

/* ============================================================================
 * Default Configuration
 * ========================================================================== */

const char *ts_get_device_name(void) {
    if (s_device_name[0] == '\0') {
        // Generate from WiFi MAC address (last 3 bytes)
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        snprintf(s_device_name, sizeof(s_device_name), "esp32-%02x%02x%02x",
                 mac[3], mac[4], mac[5]);
    }
    return s_device_name;
}

void ts_get_default_config(ts_config_t *config) {
    memset(config, 0, sizeof(ts_config_t));

    config->auth_key = NULL;           // Must be set by user
    config->device_name = ts_get_device_name();  // Auto-generated from MAC
    config->enable_derp = true;
    config->enable_stun = true;
    config->enable_disco = true;
    config->max_peers = TS_MAX_PEERS;
    config->heartbeat_interval_ms = TS_HEARTBEAT_INTERVAL_MS;
}

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

uint64_t ts_get_time_ms(void) {
    return esp_timer_get_time() / 1000;
}

const char *ts_vpn_ip_to_str(uint32_t vpn_ip, char *buffer) {
    snprintf(buffer, 16, "%lu.%lu.%lu.%lu",
             (vpn_ip >> 24) & 0xFF,
             (vpn_ip >> 16) & 0xFF,
             (vpn_ip >> 8) & 0xFF,
             vpn_ip & 0xFF);
    return buffer;
}

int ts_get_peer_count(const ts_t *ml) {
    if (!ml) return 0;
    return ml->peer_count;
}

const char *ts_state_to_str(ts_state_t state) {
    switch (state) {
        case TS_STATE_IDLE: return "IDLE";
        case TS_STATE_REGISTERING: return "REGISTERING";
        case TS_STATE_FETCHING_PEERS: return "FETCHING_PEERS";
        case TS_STATE_CONFIGURING_WG: return "CONFIGURING_WG";
        case TS_STATE_CONNECTED: return "CONNECTED";
        case TS_STATE_MONITORING: return "MONITORING";
        case TS_STATE_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

uint8_t ts_peer_find_by_vpn_ip(const ts_t *ml, uint32_t vpn_ip) {
    /* The last-octet map is only an acceleration hint; duplicate last
     * octets are valid, so fall back to the full peer table. */
    uint8_t hint = ml->peer_map[vpn_ip & 0xFF];
    if (hint < ml->peer_count && hint < TS_MAX_PEERS &&
        ml->peers[hint].vpn_ip == vpn_ip) {
        return hint;
    }
    for (uint8_t idx = 0; idx < ml->peer_count && idx < TS_MAX_PEERS; idx++) {
        if (ml->peers[idx].vpn_ip == vpn_ip) {
            return idx;
        }
    }
    return 0xFF;
}

esp_err_t ts_queue_rx_packet(ts_t *ml, const ts_packet_t *pkt) {
    uint8_t next_head = (ml->rx_head + 1) % TS_RX_QUEUE_SIZE;
    if (next_head == ml->rx_tail) {
        ml->stats.packets_dropped++;
        ESP_LOGW(TAG, "RX queue full, dropping packet");
        return ESP_ERR_NO_MEM;
    }

    memcpy(&ml->rx_queue[ml->rx_head], pkt, sizeof(ts_packet_t));
    ml->rx_head = next_head;
    ml->stats.packets_received++;
    ml->stats.bytes_received += pkt->len;

    return ESP_OK;
}

esp_err_t ts_queue_tx_packet(ts_t *ml, const ts_packet_t *pkt) {
    uint8_t next_head = (ml->tx_head + 1) % TS_TX_QUEUE_SIZE;
    if (next_head == ml->tx_tail) {
        ml->stats.packets_dropped++;
        ESP_LOGW(TAG, "TX queue full, dropping packet");
        return ESP_ERR_NO_MEM;
    }

    memcpy(&ml->tx_queue[ml->tx_head], pkt, sizeof(ts_packet_t));
    ml->tx_head = next_head;

    return ESP_OK;
}

/* ============================================================================
 * Initialization & Deinitialization
 * ========================================================================== */

ts_t *ts_init(const ts_config_t *config) {
    if (!config || !config->auth_key || !config->device_name) {
        ESP_LOGE(TAG, "Invalid configuration");
        return NULL;
    }

    // Allocate context
    ts_t *ml = calloc(1, sizeof(ts_t));
    if (!ml) {
        ESP_LOGE(TAG, "Failed to allocate context");
        return NULL;
    }

    // Copy configuration
    memcpy(&ml->config, config, sizeof(ts_config_t));

    // Initialize peer map
    memset(ml->peer_map, 0xFF, sizeof(ml->peer_map));
    memset(ml->peer_wg_indices, 0xFF, sizeof(ml->peer_wg_indices));

    // Set initial state
    ml->state = TS_STATE_IDLE;
    ml->prev_state = TS_STATE_IDLE;
    ml->state_enter_time_ms = ts_get_time_ms();

    ESP_LOGI(TAG, "Tailscale v%s initialized", TS_VERSION);
    ESP_LOGI(TAG, "Device: %s", ml->config.device_name);
    ESP_LOGI(TAG, "Features: DERP=%d STUN=%d DISCO=%d",
             ml->config.enable_derp, ml->config.enable_stun, ml->config.enable_disco);

    return ml;
}

void ts_deinit(ts_t *ml) {
    if (!ml) return;

    // Disconnect if connected
    if (ml->state != TS_STATE_IDLE) {
        ts_disconnect(ml);
    }

    // Clean up subsystems
    ts_coordination_deinit(ml);
    ts_wireguard_deinit(ml);

    if (ml->config.enable_derp) {
        ts_derp_deinit(ml);
    }

    if (ml->config.enable_stun) {
        ts_stun_deinit(ml);
    }

    // Clean up DISCO
    ts_disco_deinit(ml);

    // Free context
    free(ml);

    ESP_LOGI(TAG, "Tailscale deinitialized");
}

/* ============================================================================
 * Connection Management
 * ========================================================================== */

esp_err_t ts_connect(ts_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;

    if (ml->state != TS_STATE_IDLE) {
        ESP_LOGW(TAG, "Already connecting or connected");
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Starting connection process...");

    // Initialize subsystems
    esp_err_t ret;

    // 1. Initialize coordination client
    ret = ts_coordination_init(ml);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize coordination client: %d", ret);
        ts_set_state(ml, TS_STATE_ERROR);
        return ret;
    }

    // 2. Initialize WireGuard
    ret = ts_wireguard_init(ml);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize WireGuard: %d", ret);
        ts_set_state(ml, TS_STATE_ERROR);
        return ret;
    }

    // 3. Initialize optional subsystems
    if (ml->config.enable_stun) {
        ret = ts_stun_init(ml);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "STUN init failed, continuing without: %d", ret);
        }
    }

    if (ml->config.enable_derp) {
        ret = ts_derp_init(ml);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "DERP init failed, continuing without: %d", ret);
        }
    }

    if (ml->config.enable_disco) {
        ret = ts_disco_init(ml);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "DISCO init failed; direct path discovery disabled: %d", ret);
            // WireGuard owns UDP/51820 in the current configuration.
            // Do not attempt periodic DISCO probes with an invalid socket.
            ml->config.enable_disco = false;
        }
    }

    // Start state machine
    ts_set_state(ml, TS_STATE_REGISTERING);

    return ESP_OK;
}

esp_err_t ts_disconnect(ts_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;

    ESP_LOGI(TAG, "Disconnecting...");

    // Clean up subsystems
    ts_coordination_deinit(ml);
    ts_wireguard_deinit(ml);

    if (ml->config.enable_derp) {
        ts_derp_deinit(ml);
    }

    if (ml->config.enable_stun) {
        ts_stun_deinit(ml);
    }

    if (ml->config.enable_disco) {
        ts_disco_deinit(ml);
    }

    // Clear state
    ml->vpn_ip = 0;
    ml->peer_count = 0;
    memset(ml->peer_map, 0xFF, sizeof(ml->peer_map));
    memset(ml->peer_wg_indices, 0xFF, sizeof(ml->peer_wg_indices));
    memset(&ml->stats, 0, sizeof(ts_stats_t));

    // Trigger callback
    if (ml->config.on_disconnected) {
        ml->config.on_disconnected();
    }

    ts_set_state(ml, TS_STATE_IDLE);

    return ESP_OK;
}

esp_err_t ts_update(ts_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;

    // Run state machine
    ts_state_machine(ml);

    // Process queued TX packets
    while (ml->tx_tail != ml->tx_head) {
        ts_packet_t *pkt = &ml->tx_queue[ml->tx_tail];

        // Try WireGuard direct first
        esp_err_t ret = ts_wireguard_send(ml, pkt->dest_vpn_ip,
                                                 pkt->data, pkt->len);

        if (ret != ESP_OK && ml->config.enable_derp) {
            // Fallback to DERP
            ret = ts_derp_send(ml, pkt->dest_vpn_ip, pkt->data, pkt->len);
        }

        if (ret == ESP_OK) {
            ml->stats.packets_sent++;
            ml->stats.bytes_sent += pkt->len;
        }

        ml->tx_tail = (ml->tx_tail + 1) % TS_TX_QUEUE_SIZE;
    }

    // Try to receive packets
    ts_wireguard_receive(ml);

    if (ml->config.enable_derp) {
        ts_derp_receive(ml);
    }

    return ESP_OK;
}

/* ============================================================================
 * Data Transfer
 * ========================================================================== */

esp_err_t ts_send(ts_t *ml, uint32_t dest_vpn_ip,
                         const uint8_t *data, size_t len) {
    if (!ml || !data || len == 0 || len > TS_NETWORK_BUFFER_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!ts_is_connected(ml)) {
        return ESP_ERR_INVALID_STATE;
    }

    // Queue packet for transmission
    ts_packet_t pkt = {
        .src_vpn_ip = ml->vpn_ip,
        .dest_vpn_ip = dest_vpn_ip,
        .len = len,
        .timestamp_ms = ts_get_time_ms()
    };
    memcpy(pkt.data, data, len);

    return ts_queue_tx_packet(ml, &pkt);
}

esp_err_t ts_receive(ts_t *ml, uint32_t *src_vpn_ip,
                            uint8_t *buffer, size_t *len) {
    if (!ml || !src_vpn_ip || !buffer || !len) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!ts_is_connected(ml)) {
        return ESP_ERR_INVALID_STATE;
    }

    // Check if queue empty
    if (ml->rx_tail == ml->rx_head) {
        return ESP_ERR_NOT_FOUND;
    }

    // Dequeue packet
    ts_packet_t *pkt = &ml->rx_queue[ml->rx_tail];

    if (*len < pkt->len) {
        return ESP_ERR_INVALID_SIZE;
    }

    *src_vpn_ip = pkt->src_vpn_ip;
    *len = pkt->len;
    memcpy(buffer, pkt->data, pkt->len);

    ml->rx_tail = (ml->rx_tail + 1) % TS_RX_QUEUE_SIZE;

    return ESP_OK;
}

/* ============================================================================
 * Status Queries
 * ========================================================================== */

ts_state_t ts_get_state(const ts_t *ml) {
    return ml ? ml->state : TS_STATE_IDLE;
}

bool ts_is_connected(const ts_t *ml) {
    if (!ml) return false;
    return (ml->state == TS_STATE_CONNECTED ||
            ml->state == TS_STATE_MONITORING);
}

bool ts_is_derp_connected(const ts_t *ml) {
    return ml != NULL && ml->config.enable_derp && ml->derp.connected;
}

uint32_t ts_get_vpn_ip(const ts_t *ml) {
    return ml ? ml->vpn_ip : 0;
}

esp_err_t ts_get_peers(const ts_t *ml,
                              const ts_peer_t **peers,
                              uint8_t *count) {
    if (!ml || !peers || !count) {
        return ESP_ERR_INVALID_ARG;
    }

    *peers = ml->peers;
    *count = ml->peer_count;
    return ESP_OK;
}

esp_err_t ts_get_stats(const ts_t *ml, ts_stats_t *stats) {
    if (!ml || !stats) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(stats, &ml->stats, sizeof(ts_stats_t));
    return ESP_OK;
}

uint32_t ts_get_peer_latency(const ts_t *ml, uint32_t peer_vpn_ip) {
    if (!ml) return UINT32_MAX;

    uint8_t idx = ts_peer_find_by_vpn_ip(ml, peer_vpn_ip);
    if (idx == 0xFF) {
        return UINT32_MAX;
    }

    return ml->peers[idx].latency_ms;
}
