/**
 * @file ts_connection.c
 * @brief Tailscale connection state machine
 */

#include "ts_internal.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <unistd.h>  // For close()

static const char *TAG = "ts_conn";

/* ============================================================================
 * State Management
 * ========================================================================== */

void ts_set_state(ts_t *ml, ts_state_t new_state) {
    if (ml->state == new_state) {
        return;
    }

    ts_state_t old_state = ml->state;
    ml->prev_state = old_state;
    ml->state = new_state;
    ml->state_enter_time_ms = ts_get_time_ms();

    ESP_LOGI(TAG, "State: %s -> %s",
             ts_state_to_str(old_state),
             ts_state_to_str(new_state));

    // Trigger callback
    if (ml->config.on_state_change) {
        ml->config.on_state_change(old_state, new_state);
    }

    // Handle state transitions
    if (new_state == TS_STATE_CONNECTED) {
        // Reset reconnect counter on successful connection
        ml->coordination.reconnect_attempts = 0;
        if (ml->config.on_connected) {
            ml->config.on_connected();
        }
    }
}

/* ============================================================================
 * State Machine
 * ========================================================================== */

void ts_state_machine(ts_t *ml) {
    uint64_t now_ms = ts_get_time_ms();
    uint64_t time_in_state = now_ms - ml->state_enter_time_ms;

    switch (ml->state) {
        case TS_STATE_IDLE:
            // Waiting for ts_connect()
            break;

        case TS_STATE_REGISTERING: {
            // Rate limit registration attempts to prevent socket exhaustion
            // Only try once per second, not every 100ms update cycle
            static uint64_t last_reg_attempt = 0;
            if (now_ms - last_reg_attempt < 1000) {
                break;  // Wait before next attempt
            }
            last_reg_attempt = now_ms;

            // Register with Tailscale coordination server
            esp_err_t ret = ts_coordination_register(ml);

            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "Registration successful");
                char ip_buf[16];
                ESP_LOGI(TAG, "VPN IP: %s",
                         ts_vpn_ip_to_str(ml->vpn_ip, ip_buf));

                // Send MapRequest IMMEDIATELY after registration to keep connection alive
                // DERPRegion will be 0 initially, we'll update later
                ts_set_state(ml, TS_STATE_FETCHING_PEERS);
            } else if (time_in_state > 30000) {
                // Timeout after 30 seconds (increased from 10s to allow more retries)
                ESP_LOGE(TAG, "Registration timeout");
                ts_set_state(ml, TS_STATE_ERROR);
            }
            break;
        }

        case TS_STATE_FETCHING_PEERS: {
            // Run STUN FIRST so MapRequest includes our public endpoint
            // This is CRITICAL - without endpoints, peers can't reach us directly
            // Use static flag to ensure STUN runs exactly once per state entry
            static bool stun_attempted = false;
            static uint64_t stun_start_time = 0;

            if (ml->config.enable_stun && !stun_attempted) {
                stun_attempted = true;
                stun_start_time = now_ms;
                ESP_LOGI(TAG, "Running STUN probe BEFORE MapRequest to discover endpoint...");
                esp_err_t stun_ret = ts_stun_probe(ml);
                if (stun_ret == ESP_OK) {
                    ESP_LOGI(TAG, "STUN probe initiated, waiting for response...");
                } else {
                    ESP_LOGW(TAG, "STUN probe failed: %d (continuing without STUN endpoint)", stun_ret);
                }
                break;  // Return and wait for STUN to complete
            }

            // Wait up to 500ms for STUN response before sending MapRequest
            if (ml->config.enable_stun && stun_attempted && (now_ms - stun_start_time) < 500) {
                break;  // Give STUN time to complete
            }

            // Reset flag for next time we enter this state
            stun_attempted = false;

            // Fetch peer list from coordination server
            // STUN should be done now so Endpoints are included in MapRequest
            esp_err_t ret = ts_coordination_fetch_peers(ml);

            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "Fetched %d peers", ml->peer_count);
                ts_set_state(ml, TS_STATE_CONFIGURING_WG);
            } else if (time_in_state > 30000) {
                // Timeout after 30 seconds (longer for Stream=true mode)
                ESP_LOGE(TAG, "Peer fetch timeout");
                ts_set_state(ml, TS_STATE_ERROR);
            }
            break;
        }

        case TS_STATE_CONFIGURING_WG: {
            // Connect to DERP FIRST - we need it for reliable handshakes
            // DERP-first strategy: all handshakes go through DERP relay initially,
            // then upgrade to direct UDP via DISCO if possible
            if (ml->config.enable_derp && !ml->derp.connected) {
                static bool derp_connect_started = false;
                if (!derp_connect_started) {
                    ESP_LOGI(TAG, "Connecting to DERP relay FIRST (for reliable handshakes)...");
                    ts_derp_connect(ml);
                    derp_connect_started = true;
                }
                // Wait for DERP to connect before adding peers
                if (!ml->derp.connected) {
                    // Give DERP time to connect, but don't wait forever
                    if (time_in_state > 10000) {
                        ESP_LOGW(TAG, "DERP connection timeout, proceeding without DERP");
                        derp_connect_started = false;  // Reset for next attempt
                    } else {
                        break;  // Wait for DERP
                    }
                }
                derp_connect_started = false;  // Reset for reconnections
                ESP_LOGI(TAG, "DERP connected, waiting for socket to stabilize...");
                vTaskDelay(pdMS_TO_TICKS(500));  // Give TLS socket time to stabilize
                ESP_LOGI(TAG, "Now adding peers...");
            }

            // Add peers to WireGuard (handshakes will use DERP)
            for (uint8_t i = 0; i < ml->peer_count; i++) {
                esp_err_t ret = ts_wireguard_add_peer(ml, &ml->peers[i]);
                if (ret != ESP_OK) {
                    ESP_LOGW(TAG, "Failed to add peer %d", i);
                }
                // Process queued DERP packets after each peer to prevent queue overflow
                // Handshakes queue packets immediately, need to drain the queue
                ts_wireguard_process_derp_queue();
                vTaskDelay(pdMS_TO_TICKS(50));  // Brief delay for DERP send to complete
            }

            // STUN already done in FETCHING_PEERS state

            ESP_LOGI(TAG, "WireGuard configured");
            ts_set_state(ml, TS_STATE_CONNECTED);
            break;
        }

        case TS_STATE_CONNECTED: {
            // Process any pending DERP queue items during transition
            ts_wireguard_process_derp_queue();

            // The poll task is now started in ts_coordination_fetch_peers()
            // immediately after the long-poll is established, to avoid nonce desync.
            // Here we just transition to MONITORING after a brief delay.
            if (time_in_state > 1000) {
                ts_set_state(ml, TS_STATE_MONITORING);
            }
            break;
        }

        case TS_STATE_MONITORING: {
            // Log periodic heartbeat to show we're alive
            static uint64_t last_alive_log = 0;
            if (now_ms - last_alive_log >= 60000) {
                ESP_LOGI(TAG, "MONITORING: alive, DERP=%s, peers=%d, vpn_ip=%d.%d.%d.%d, frames=%lu",
                         ml->derp.connected ? "connected" : "disconnected",
                         ml->peer_count,
                         (ml->vpn_ip >> 24) & 0xFF, (ml->vpn_ip >> 16) & 0xFF,
                         (ml->vpn_ip >> 8) & 0xFF, ml->vpn_ip & 0xFF,
                         (unsigned long)ml->coordination.frames_processed);
                last_alive_log = now_ms;
            }

            // === Dual-Core Fix: Check for errors from the Core 1 poll task ===
            if (ts_coordination_check_error(ml)) {
                ESP_LOGW(TAG, "Core 1 poll task detected connection error, reconnecting...");
                ts_coordination_stop_poll_task(ml);

                // Close the stale socket and mark for reconnection
                if (ml->coordination.socket >= 0) {
                    close(ml->coordination.socket);
                    ml->coordination.socket = -1;
                }
                ml->coordination.registered = false;
                ml->coordination.handshake_complete = false;
                ml->coordination.reconnect_attempts++;

                // Transition to re-register
                ts_set_state(ml, TS_STATE_REGISTERING);
                break;
            }

            // Check if server sent GOAWAY - need to reconnect
            if (ml->coordination.goaway_received) {
                ESP_LOGI(TAG, "GOAWAY received, reconnecting to coordination server...");
                ml->coordination.goaway_received = false;

                // Stop the poll task first
                ts_coordination_stop_poll_task(ml);

                // Close the stale socket
                if (ml->coordination.socket >= 0) {
                    close(ml->coordination.socket);
                    ml->coordination.socket = -1;
                }
                ml->coordination.registered = false;
                ml->coordination.handshake_complete = false;
                ml->coordination.reconnect_attempts++;

                // Add backoff delay (1s, 2s, 4s, max 30s)
                uint32_t backoff_ms = 1000 << (ml->coordination.reconnect_attempts > 4 ? 4 : ml->coordination.reconnect_attempts);
                if (backoff_ms > 30000) backoff_ms = 30000;
                ESP_LOGI(TAG, "Reconnect attempt %d, backoff %lu ms",
                         ml->coordination.reconnect_attempts, (unsigned long)backoff_ms);
                ml->coordination.last_reconnect_ms = now_ms;

                // Small delay before reconnecting
                vTaskDelay(pdMS_TO_TICKS(backoff_ms));

                // Reconnect DERP relay as well (session context changed)
                ESP_LOGI(TAG, "Also reconnecting DERP relay after GOAWAY...");
                esp_err_t derp_ret = ts_derp_reconnect(ml);
                if (derp_ret != ESP_OK) {
                    ESP_LOGW(TAG, "DERP reconnect failed: %d (will retry later)", derp_ret);
                }

                // Transition to re-register
                ts_set_state(ml, TS_STATE_REGISTERING);
                break;
            }

            // Check session health periodically
            esp_err_t session_ret = ts_coordination_check_session(ml);
            if (session_ret != ESP_OK) {
                ESP_LOGW(TAG, "Session check failed, triggering re-registration");
                ts_coordination_stop_poll_task(ml);
                ts_coordination_handle_key_rotation(ml);
                ts_set_state(ml, TS_STATE_REGISTERING);
                break;
            }

            // Send heartbeat periodically
            // NOTE: The Core 1 task handles HTTP/2 PINGs, but heartbeat is protocol-level
            uint64_t since_heartbeat = now_ms - ml->coordination.last_heartbeat_ms;
            if (since_heartbeat >= ml->config.heartbeat_interval_ms) {
                esp_err_t ret = ts_coordination_heartbeat(ml);
                if (ret != ESP_OK) {
                    ESP_LOGW(TAG, "Heartbeat failed: %d", ret);
                    // Session may be invalid, transition to error state for reconnection
                    if (ret == ESP_ERR_INVALID_STATE) {
                        ts_coordination_stop_poll_task(ml);
                        ts_coordination_handle_key_rotation(ml);
                        ts_set_state(ml, TS_STATE_ERROR);
                        break;
                    }
                }
                ml->coordination.last_heartbeat_ms = now_ms;
            }

            // === Dual-Core Fix: The Core 1 task now handles coordination polling ===
            // We only need to do occasional checks here, not continuous polling
            // This allows DISCO/DERP to run on Core 0 without blocking coordination
            uint64_t since_map_poll = now_ms - ml->coordination.last_map_poll_ms;
            if (since_map_poll >= 30000) {  // Reduced frequency - Core 1 handles real-time polling
                // Only poll if Core 1 task isn't running (fallback mode)
                if (ml->coordination.poll_task_handle == NULL) {
                    esp_err_t poll_ret = ts_coordination_poll_updates(ml);
                    if (poll_ret == ESP_ERR_INVALID_STATE) {
                        ESP_LOGW(TAG, "Long-poll connection lost, will reconnect");
                        if (ml->coordination.socket >= 0) {
                            close(ml->coordination.socket);
                            ml->coordination.socket = -1;
                        }
                        ml->coordination.registered = false;
                        ml->coordination.handshake_complete = false;
                        ts_set_state(ml, TS_STATE_REGISTERING);
                        break;
                    }
                }
                ml->coordination.last_map_poll_ms = now_ms;
            }

            // Run DISCO probes if enabled
            // NOTE: Core 1 handles coordination, so DISCO can run freely on Core 0
            if (ml->config.enable_disco) {
                // Always check for incoming DISCO packets (PONGs) - this must be frequent!
                ts_disco_update_paths(ml);

                // Send probes less frequently (every 30 seconds)
                uint64_t since_disco = now_ms - ml->disco.last_global_disco_ms;
                if (since_disco >= TS_DISCO_INTERVAL_MS) {
                    ts_disco_probe_peers(ml);
                    ml->disco.last_global_disco_ms = now_ms;
                }
            }

            // Run STUN probes if enabled
            if (ml->config.enable_stun) {
                uint64_t since_stun = now_ms - ml->stun.last_probe_ms;
                if (since_stun >= TS_STUN_INTERVAL_MS) {
                    ts_stun_probe(ml);
                    ml->stun.last_probe_ms = now_ms;
                }
            }

            // Process incoming DERP packets if enabled
            if (ml->config.enable_derp) {
                if (ml->derp.connected) {
                    ts_derp_receive(ml);
                } else {
                    // DERP dropped - try to reconnect periodically
                    static uint64_t last_derp_retry = 0;
                    if (now_ms - last_derp_retry >= 10000) {  // Retry every 10s
                        ESP_LOGW(TAG, "DERP disconnected, attempting reconnect...");
                        ts_derp_reconnect(ml);
                        last_derp_retry = now_ms;
                    }
                }
            }

            // Process any queued DERP packets from WireGuard timer callbacks
            // These were deferred because the timer runs with insufficient stack
            ts_wireguard_process_derp_queue();

            break;
        }

        case TS_STATE_ERROR: {
            // Retry connection after delay
            if (time_in_state >= TS_RECONNECT_DELAY_MS) {
                ESP_LOGI(TAG, "Retrying connection...");
                ts_disconnect(ml);
                ts_connect(ml);
            }
            break;
        }
    }
}
