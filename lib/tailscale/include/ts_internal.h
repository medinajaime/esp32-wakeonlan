/**
 * @file ts_internal.h
 * @brief Tailscale internal definitions and structures
 */

#ifndef TS_INTERNAL_H
#define TS_INTERNAL_H

#include "ts.h"
#include "esp_timer.h"
#include "mbedtls/ssl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Dual-Core Configuration (ECONNRESET Fix)
 * ========================================================================== */

// Core assignments for dual-core ESP32-S3
#define TS_COORDINATION_CORE  1    // Core 1: High-priority coordination polling
#define TS_MAIN_CORE          0    // Core 0: DERP, DISCO, state machine

// Coordination buffer size (configurable via menuconfig)
// Default 64KB for PSRAM devices, use 24-32KB for ESP32 without PSRAM
#ifdef CONFIG_TS_COORD_BUFFER_SIZE_KB
#define TS_COORD_BUFFER_SIZE  (CONFIG_TS_COORD_BUFFER_SIZE_KB * 1024)
#else
#define TS_COORD_BUFFER_SIZE  (64 * 1024)  // Default 64KB for large MapResponses
#endif
#define TS_COORD_TASK_STACK   (8 * 1024)   // 8KB stack for coordination task
#define TS_COORD_TASK_PRIORITY (configMAX_PRIORITIES - 1)  // Highest priority

// Polling intervals for coordination task
// Note: Lower values = more responsive but more CPU/heat. Higher = cooler but slower response.
#define TS_COORD_POLL_INTERVAL_MS  50   // 50ms = 20Hz polling (reduced from 100Hz for thermal stability)
#define TS_COORD_PING_INTERVAL_MS  5000 // 5 seconds between HTTP/2 PINGs

/* ============================================================================
 * Internal Constants
 * ========================================================================== */

// Buffer sizes
#define TS_RX_QUEUE_SIZE 8
#define TS_TX_QUEUE_SIZE 8
#define TS_PEER_MAP_SIZE 256  // 256 possible IPs in 100.64.0.0/10

// Noise protocol constants (ts2021)
#define NOISE_KEY_SIZE 32
#define NOISE_NONCE_SIZE 12
#define NOISE_MAC_SIZE 16

// DERP region limits
#define TS_MAX_DERP_REGIONS 32  // Max DERP regions to track from DERPMap (Tailscale has ~25 regions)

/* ============================================================================
 * Internal Structures
 * ========================================================================== */

/**
 * @brief DERP region info (parsed from MapResponse DERPMap)
 */
typedef struct {
    uint16_t region_id;                 ///< Region ID (e.g., 1=NYC, 9=Dallas)
    char hostname[64];                  ///< DERP server hostname (e.g., "derp1.tailscale.com")
    uint16_t port;                      ///< Port (usually 443)
    bool available;                     ///< True if this region is available in tailnet config
} ts_derp_region_t;

/**
 * @brief Network packet buffer
 */
typedef struct {
    uint32_t src_vpn_ip;                ///< Source VPN IP
    uint32_t dest_vpn_ip;               ///< Destination VPN IP
    uint8_t data[TS_NETWORK_BUFFER_SIZE];
    size_t len;
    uint64_t timestamp_ms;              ///< Receive timestamp
} ts_packet_t;

/**
 * @brief Coordination client state
 *
 * NOTE: This struct is accessed from two cores:
 * - Core 0: State machine, registration, initial setup
 * - Core 1: Dedicated coordination polling task (poll_updates)
 *
 * The mutex protects shared state during concurrent access.
 */
typedef struct {
    // Machine keys (Curve25519 keypair)
    uint8_t machine_private_key[NOISE_KEY_SIZE];  ///< Machine private key (s)
    uint8_t machine_public_key[NOISE_KEY_SIZE];   ///< Machine public key (s.pub)
    char machine_key[65];                          ///< Machine key string (base64)

    // Noise transport keys (derived after handshake)
    uint8_t tx_key[NOISE_KEY_SIZE];                ///< Client->Server encryption key
    uint8_t rx_key[NOISE_KEY_SIZE];                ///< Server->Client decryption key
    uint64_t tx_nonce;                             ///< Transmission nonce counter
    uint64_t rx_nonce;                             ///< Reception nonce counter
    bool handshake_complete;

    // Connection state
    int socket;                                    ///< TCP socket for Noise connection
    bool registered;                               ///< Device registered with server
    bool goaway_received;                          ///< Server sent GOAWAY, need to reconnect
    uint8_t reconnect_attempts;                    ///< Number of reconnect attempts
    uint32_t next_stream_id;                       ///< Next HTTP/2 stream ID (odd numbers: 1, 3, 5, ...)

    // Registration info
    uint32_t node_id;                              ///< Our node ID
    uint64_t node_key;                             ///< Signed node key

    // Timing
    uint64_t last_heartbeat_ms;
    uint64_t last_map_poll_ms;
    uint64_t last_ping_ms;                         ///< Last HTTP/2 PING time (for keep-alive)
    uint64_t last_reconnect_ms;                    ///< Last reconnect attempt time

    // === Dual-Core PSRAM Fix (ECONNRESET solution) ===
    TaskHandle_t poll_task_handle;                 ///< Handle for dedicated Core 1 polling task
    SemaphoreHandle_t mutex;                       ///< Mutex for thread-safe access to shared state
    uint8_t *psram_buffer;                         ///< 64KB buffer in PSRAM for large MapResponses
    volatile bool poll_task_running;               ///< Flag to signal task to stop
    volatile bool connection_error;                ///< Flag set by poll task when connection fails
    volatile uint32_t frames_processed;            ///< Counter for frames processed by poll task
} ts_coordination_t;

/**
 * @brief DERP client state
 */
typedef struct {
    // TLS connection
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_cert;
    int sockfd;                         ///< Socket file descriptor

    bool connected;
    uint32_t our_derp_id;               ///< Our DERP client ID
    uint64_t last_keepalive_ms;

    // Dynamic DERP region discovery (optional feature - parsed from MapResponse DERPMap)
    // When enabled, Tailscale will use the DERP regions advertised by Tailscale instead of hardcoded values.
    // This is useful when the tailnet has custom derpMap configurations that disable certain regions.
    // Default: disabled (uses TS_DERP_SERVER/TS_DERP_REGION from Kconfig)
    ts_derp_region_t regions[TS_MAX_DERP_REGIONS];
    uint8_t region_count;               ///< Number of discovered DERP regions (0 = use hardcoded)
    uint8_t current_region_idx;         ///< Index of currently connected region
    bool dynamic_discovery_enabled;     ///< True to use DERPMap from server, false for hardcoded
} ts_derp_t;

/**
 * @brief STUN client state
 */
typedef struct {
    int sock_fd;                        ///< UDP socket for STUN
    void *netif;                        ///< lwIP network interface (struct netif*)
    uint32_t public_ip;                 ///< Discovered public IP
    uint16_t public_port;               ///< Discovered public port
    uint32_t advertised_ip;             ///< Public IP last advertised to the coordination server
    uint16_t advertised_port;           ///< Public port last advertised to the coordination server
    uint64_t last_probe_ms;
    bool nat_detected;
} ts_stun_t;

/**
 * @brief DISCO protocol state
 */
typedef struct {
    // Per-peer DISCO state
    struct {
        uint64_t last_probe_ms;
        uint64_t last_pong_sent_ms;     ///< Rate-limit PONG responses (from dj-oyu fork)
        uint32_t probe_sequence;
        bool active;
    } peer_disco[TS_MAX_PEERS];

    uint64_t last_global_disco_ms;
    uint16_t local_port;                ///< Local port for DISCO socket (used in CallMeMaybe)
} ts_disco_t;

/**
 * @brief WireGuard state (placeholder for library integration)
 */
typedef struct {
    uint8_t private_key[32];
    uint8_t public_key[32];
    uint8_t disco_private_key[32];      ///< Disco key pair for peer discovery
    uint8_t disco_public_key[32];
    char private_key_b64[64];           ///< Base64-encoded private key for wireguard-lwip
    uint16_t listen_port;
    void *netif;                        ///< lwIP network interface (struct netif*)
    bool initialized;
} ts_wireguard_t;

/**
 * @brief Main Tailscale context
 */
struct ts_context {
    // Configuration
    ts_config_t config;

    // State
    ts_state_t state;
    ts_state_t prev_state;
    uint64_t state_enter_time_ms;

    // VPN identity
    uint32_t vpn_ip;                    ///< Our VPN IP (100.x.x.x)

    // Peers
    ts_peer_t peers[TS_MAX_PEERS];
    uint8_t peer_count;
    uint8_t peer_map[TS_PEER_MAP_SIZE];  // vpn_ip_last_byte -> peer index
    uint8_t peer_wg_indices[TS_MAX_PEERS]; // peer table index -> WireGuard slot

    // Subsystems
    ts_coordination_t coordination;
    ts_wireguard_t wireguard;
    ts_derp_t derp;
    ts_stun_t stun;
    ts_disco_t disco;

    // Packet queues
    ts_packet_t rx_queue[TS_RX_QUEUE_SIZE];
    uint8_t rx_head;
    uint8_t rx_tail;
    ts_packet_t tx_queue[TS_TX_QUEUE_SIZE];
    uint8_t tx_head;
    uint8_t tx_tail;

    // Statistics
    ts_stats_t stats;

    // Timers
    esp_timer_handle_t update_timer;
};

/* ============================================================================
 * Internal Function Declarations
 * ========================================================================== */

// State machine (ts_connection.c)
void ts_state_machine(ts_t *ml);
void ts_set_state(ts_t *ml, ts_state_t new_state);

// Coordination client (ts_coordination.c)
esp_err_t ts_coordination_init(ts_t *ml);
esp_err_t ts_coordination_deinit(ts_t *ml);
esp_err_t ts_coordination_register(ts_t *ml);
esp_err_t ts_coordination_fetch_peers(ts_t *ml);
esp_err_t ts_coordination_heartbeat(ts_t *ml);
esp_err_t ts_coordination_handle_key_rotation(ts_t *ml);
esp_err_t ts_coordination_check_session(ts_t *ml);
esp_err_t ts_coordination_poll_updates(ts_t *ml);  // Poll long-poll connection for updates
esp_err_t ts_coordination_regenerate_machine_key(ts_t *ml);
esp_err_t ts_factory_reset(void);  // Erase ALL stored keys - call BEFORE ts_init()

// Dual-Core Coordination Task (ECONNRESET fix)
esp_err_t ts_coordination_start_poll_task(ts_t *ml);   // Start Core 1 polling task
esp_err_t ts_coordination_stop_poll_task(ts_t *ml);    // Stop Core 1 polling task
bool ts_coordination_check_error(ts_t *ml);            // Check if poll task detected error

// DERP client (ts_derp.c)
esp_err_t ts_derp_init(ts_t *ml);
esp_err_t ts_derp_deinit(ts_t *ml);
esp_err_t ts_derp_connect(ts_t *ml);
esp_err_t ts_derp_reconnect(ts_t *ml);
esp_err_t ts_derp_send(ts_t *ml, uint32_t dest_vpn_ip,
                              const uint8_t *data, size_t len);
esp_err_t ts_derp_send_raw(ts_t *ml, const uint8_t *dest_pubkey,
                                   const uint8_t *data, size_t len);  // Send using raw pubkey
esp_err_t ts_derp_receive(ts_t *ml);

// STUN client (ts_stun.c)
esp_err_t ts_stun_init(ts_t *ml);
esp_err_t ts_stun_deinit(ts_t *ml);
esp_err_t ts_stun_probe(ts_t *ml);

// DISCO protocol (ts_disco.c)
esp_err_t ts_disco_init(ts_t *ml);
esp_err_t ts_disco_deinit(ts_t *ml);
esp_err_t ts_disco_probe_peers(ts_t *ml);
esp_err_t ts_disco_update_paths(ts_t *ml);
esp_err_t ts_disco_handle_derp_packet(ts_t *ml, const uint8_t *src_key,
                                              const uint8_t *data, size_t len);
bool ts_disco_is_disco_packet(const uint8_t *data, size_t len);
esp_err_t ts_disco_send_call_me_maybe(ts_t *ml, uint32_t peer_vpn_ip);
int ts_disco_get_socket(void);  // Get DISCO socket fd for magicsock mode

// WireGuard wrapper (will integrate with WireGuard-ESP32-Arduino)
esp_err_t ts_wireguard_init(ts_t *ml);
esp_err_t ts_wireguard_deinit(ts_t *ml);
esp_err_t ts_wireguard_add_peer(ts_t *ml, const ts_peer_t *peer);
esp_err_t ts_wireguard_update_endpoint(ts_t *ml, uint32_t vpn_ip,
                                               uint32_t endpoint_ip, uint16_t endpoint_port);
esp_err_t ts_wireguard_trigger_handshake(ts_t *ml, uint32_t vpn_ip);
esp_err_t ts_wireguard_send(ts_t *ml, uint32_t dest_vpn_ip,
                                   const uint8_t *data, size_t len);
esp_err_t ts_wireguard_receive(ts_t *ml);
esp_err_t ts_wireguard_inject_derp_packet(ts_t *ml, uint32_t src_vpn_ip,
                                                  const uint8_t *data, size_t len);
esp_err_t ts_wireguard_inject_packet(ts_t *ml, uint32_t src_ip, uint16_t src_port,
                                             const uint8_t *data, size_t len);  // Magicsock: inject with port
void ts_wireguard_get_public_key(const ts_t *ml, uint8_t *public_key);
esp_err_t ts_wireguard_set_vpn_ip(ts_t *ml, uint32_t vpn_ip);
void ts_wireguard_process_derp_queue(void);
esp_err_t ts_wireguard_enable_magicsock(ts_t *ml);  // Enable magicsock mode (WG uses DISCO socket)

// Utility functions
uint64_t ts_get_time_ms(void);
uint8_t ts_peer_find_by_vpn_ip(const ts_t *ml, uint32_t vpn_ip);
esp_err_t ts_queue_rx_packet(ts_t *ml, const ts_packet_t *pkt);
esp_err_t ts_queue_tx_packet(ts_t *ml, const ts_packet_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* TS_INTERNAL_H */
