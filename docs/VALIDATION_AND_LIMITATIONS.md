# Validation evidence and security limitations

## Environment

- **Hardware:** ESP32-WROOM-32D dev kit; 4 MB flash; no PSRAM
- **Firmware framework:** ESP-IDF 5.5.3 on Windows PowerShell
- **Target:** Ethernet-connected Toshiba laptop running Proxmox VE 9.2.2
- **Client:** Android tablet with Tailscale; observed relayed/DERP path
- **Transport:** UDP wake trigger to the ESP32's Tailscale address on port 9999,
  followed by a local LAN Wake-on-LAN magic packet

## Observed results, 10 November 2026

| Test | Evidence | Result |
|---|---|---|
| ESP32 registration | Serial logs: registration and MapResponse VPN address assigned | PASS |
| DERP relay connection | DERP session activity and relayed Tailscale ping from tablet | PASS for observed session |
| ESP-IDF build of v3 + v4 | `Project build complete`; app image `0xEB7A0`, 37% app-partition free | PASS |
| Startup after app-only flash | Normal boot, Tailscale registration and relay traffic | PASS in observed run |
| First complete-shutdown wake | Tablet UDP send; laptop indicators on; Proxmox GUI accessible | PASS |
| Shutdown and second wake | Shutdown from Proxmox; only power/charging indicator remained; second UDP send successfully booted and GUI returned | PASS |
| Direct UDP / STUN | STUN timed out; DISCO socket had bind conflict | NOT VALIDATED |
| Repeated disconnect/reconnect under stress | No controlled multi-cycle stress run | NOT VALIDATED |
| Long-term operation and heap use | No endurance benchmark | NOT VALIDATED |
| Authorized command-only wake | Application payload-validation code not fully audited | NOT VALIDATED |
| DERP TLS certificate authentication | `MBEDTLS_SSL_VERIFY_NONE` identified in reviewed source | SECURITY BLOCKER |

Two wake tests are **evidence of working end-to-end behavior**, not proof of
uninterrupted uptime, resistance to attacker traffic or every Tailscale route.
The ping measured relay latency in the hundreds of milliseconds; it should
not be interpreted as direct-path performance.

## Persistent-identity / flash precautions

On the tested device, the partition table matched the built layout:

```text
nvs,data,nvs,0x9000,24K,
phy_init,data,phy,0xf000,4K,
factory,app,factory,0x10000,1500K,
```

The app-only flash wrote the application at `0x10000` and did not itself
rewrite the NVS partition. The existing Tailscale/WireGuard identity was
reported as loaded from NVS after startup. App firmware **can still write NVS
at runtime**; neither app-only flash nor the partition check protects against
all software errors. Keep an off-repository full-flash backup.

For this device and only when the partition layout has been verified:

```powershell
python "$env:IDF_PATH\tools\idf.py" build
python "$env:IDF_PATH\tools\idf.py" -p COM4 app-flash
python "$env:IDF_PATH\tools\idf.py" -p COM4 monitor
```

Do not run `erase-flash`, flash arbitrary offsets, or re-run guided setup
without understanding its impact on configuration and persistent identity.

## Security status and next gates

1. **DERP TLS certificate verification**: current reviewed implementation
   disables server-certificate authentication; enable verification with a
   trust store and correct device time, then test failure behavior.
2. **WoL command authorization**: inspect `main/main.c` and restrict exact
   accepted payload; use restrictive Tailscale grants/ACLs to UDP/9999,
   rate limiting, and never expose a public router port-forward for WoL.
3. **Network protocol hardening**: audit concurrent Noise nonce ownership,
   fragmented TCP/HTTP2 parsing and malformed payload response.
4. **Memory/lifecycle durability**: measure free/minimum heap, TCP/IP task
   stack (configured 3072 bytes during the test), repeated reconnect and
   clean teardown without dangling callbacks.
5. **Release hygiene**: scan the staged source for secrets. Never publish
   `sdkconfig`, Wi-Fi/auth credentials, NVS keys, flash dumps or embedded
   firmware images containing credentials.

**Status: validated functional lab milestone, not production-secure.**
