# Final implementation changes relative to upstream

**Scope:** Tested ESP32-WROOM-32D dev kit adaptation, 10 November 2026. This is
an account of the **final changes kept in the working firmware**, not a history
of failed experiments. Original code and setup are attributed in
[UPSTREAM_ATTRIBUTION.md](UPSTREAM_ATTRIBUTION.md).

## Baseline and provenance

The upstream [medinajaime/esp32-wakeonlan](https://github.com/medinajaime/esp32-wakeonlan)
provides the ESP32/Tailscale/WoL architecture, setup scripts, UDP trigger and
magic-packet sender. The local working branch was based on a clone described
in the lab as upstream revision `e87e3ef`; **verify the full baseline commit
with `git rev-parse HEAD` before claiming an exact revision**. The available
review includes original/modified source snapshots, accumulated Git diffs
and device logs; it does not constitute a fully reconstructed upstream-to-head
patch review of every file in the repository.

On the Windows checkout, the staged six-C-file comparison gave **639 additions,
543 deletions** with end-of-line whitespace ignored. This figure reflects the
accumulated code changes, not an ownership claim or an accurate line count per
feature. A normal diff was much larger because of CRLF/LF transformations.

## Retained changes in the tested firmware

| Module | Final adaptation | Reason |
|---|---|---|
| `lib/tailscale/src/ts_coordination.c` | Additional Noise frame length/type/tag checks; HTTP/2/MapResponse bounds and framing checks; safer decrypt-buffer lifetime; nonce updates after authenticated decrypt; guarded receive buffering; reduced raw payload/JSON/auth logging; NVS identity handling. | Reduce out-of-bounds reads/writes, underflow, data exposure and malformed-network-input failures. |
| `lib/tailscale/src/ts_wireguard.c` | Restore proper init data and input handling for `wireguardif_init()`; guard device cleanup; enforce lwIP pbuf length/copy checks; improve NVS key persistence; add bounded, synchronized, deferred DERP packet queue; run lifecycle operations on lwIP's TCP/IP thread. | Correct initialization and memory ownership; reduce unreliable relay sends and cross-core races. |
| `lib/tailscale/src/ts_derp.c` | Serialized TLS writes with clearer timeout handling; reconnect after partial-frame failures; remove private-key/nonce dumps; defer transient sends rather than aggressively dropping them. | Preserve DERP stream framing and reduce packet loss and logging risk. |
| `lib/tailscale/src/ts_connection.c` | Use reconnect path for a lost DERP session. | Avoid reusing stale TLS/socket state. |
| `lib/tailscale/src/ts.c` | Disable repeated direct-path probes when DISCO socket initialization fails. | Keep the working relay path usable despite UDP/51820 bind conflict. |
| `lib/tailscale/components/wireguard_lwip/src/wireguardif.c` | Cancel recurring `wireguardif_tmr()` before device free; add lifecycle shutdown helper. | Address use-after-free risk during teardown. |

The reviewed implementation uses a **32-entry / 8 KiB maximum** DERP queue,
with retry limits; it does not guarantee exactly-once delivery. The DISCO
socket-port conflict was **not fully redesigned** and direct UDP connectivity
was **not validated**. The working scenario uses DERP relay.

## Scope boundaries

This change set does **not** claim: a newly written Tailscale client, a new
WireGuard cryptographic implementation, validated direct UDP/STUN, audited
application authorization, guaranteed delivery, high-availability operation,
or production security. Original setup code, component dependencies and
third-party copyright notices remain upstream-derived.

## How to compare against the checked-out baseline

From the original local Git checkout, before creating the milestone commit:

```powershell
git rev-parse HEAD
git status --short
git diff --cached --ignore-space-at-eol --stat
git diff --cached --ignore-space-at-eol -- lib/tailscale/src/ts_coordination.c lib/tailscale/src/ts_wireguard.c
```

For the full staged source delta, run:

```powershell
git diff --cached --ignore-space-at-eol -- lib/tailscale/src lib/tailscale/components/wireguard_lwip/src/wireguardif.c
```

Keep source snapshots, patches and private firmware backups outside a public
Git repository. Avoid using the raw `git diff --stat` insertion count as a
feature count when CRLF/LF differs from the upstream index.
