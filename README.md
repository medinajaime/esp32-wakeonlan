# ESP32 Wake-on-LAN via Tailscale

Wake up a PC on your home network from anywhere through Tailscale, using the
**ESP32-WROOM-32D dev kit** as a small always-on Wake-on-LAN bridge.

```text
[You, anywhere] --Tailscale--> [ESP32 on LAN] --UDP broadcast--> [Sleeping PC]
```

The ESP32 joins your tailnet, listens for a UDP trigger, and broadcasts a WoL
magic packet on your local network.

## How It Works

1. The ESP32 boots, connects to WiFi, and registers with Tailscale.
2. The firmware keeps a UDP listener open on port `9999` by default.
3. Any allowed Tailscale peer sends a wake trigger to the ESP32.
4. The ESP32 broadcasts a WoL magic packet on the LAN.
5. The target PC's Ethernet NIC receives the packet and powers on.

## Tested adaptation — 10 November 2026

This repository adapts the original project for an **ESP32-WROOM-32D dev kit**
(4 MB flash, no PSRAM) and an Ethernet-connected Proxmox host. The firmware
was built with **ESP-IDF v5.5.3**, and an Android Tailscale peer successfully
woke the target from complete shutdown **twice**, including a shutdown between
the tests. The observed Tailscale path was **DERP-relayed**; direct UDP was not
validated.

Relative to upstream, the local changes cover safer Noise/HTTP2 parsing and
key persistence, WireGuard initialization, DERP queue/reconnect handling, and
lwIP timer lifecycle. They were developed and reviewed with AI assistance,
then built and tested on the actual device. This is a tested adaptation, **not
an independently implemented Tailscale/WireGuard stack**.

- [Final implementation differences from upstream](docs/CHANGES_FROM_UPSTREAM.md)
- [Hardware validation, limitations and security status](docs/VALIDATION_AND_LIMITATIONS.md)
- [Upstream developers, third-party credits and licensing](docs/UPSTREAM_ATTRIBUTION.md)

**Security status:** Functionally validated for this wake scenario and
substantially hardened relative to the reviewed upstream baseline. The
implementation includes additional parser validation, key-persistence safeguards,
DERP queue/reconnect improvements, reduced sensitive logging and WireGuard/lwIP
lifecycle fixes. However, authenticated DERP TLS certificate verification
remains an open blocker, and the UDP wake-command authorization model still
requires a dedicated security audit.

### Security improvements relative to upstream

- Added validation for untrusted Noise frame lengths before parsing or
  decryption.
- Added HTTP/2 frame bounds checking to reduce out-of-bounds read risks.
- Corrected Noise nonce advancement so receive nonces are updated only after
  successful authentication.
- Removed logging of WireGuard keys, Noise keys, nonces, challenge responses,
  encrypted payloads and other sensitive protocol material.
- Hardened persistent identity handling by failing closed on NVS storage errors
  instead of silently generating replacement identities.
- Added validation and bounds checks around peer, endpoint and protocol data
  received from coordination servers.
- Improved DERP framing and reconnect behavior after partial-frame failures.
- Reworked DERP packet queuing with bounded memory usage, retry limits, aging
  and duplicate suppression.
- Moved WireGuard lifecycle operations to lwIP's TCP/IP thread to better align
  with lwIP ownership requirements.
- Added explicit WireGuard timer shutdown handling to reduce use-after-free risk
  during interface teardown.

### Areas still requiring review

The implementation is not considered production-secure.

Known security gaps include:

1. **DERP TLS certificate verification remains disabled.**
   Reviewed code paths still use `MBEDTLS_SSL_VERIFY_NONE`, meaning DERP server
   identity is not cryptographically verified.

2. **Wake-command authorization has not been independently audited.**
   The WoL trigger mechanism should be protected with restrictive Tailscale ACLs
   and should never be exposed through public Internet port-forwarding.

3. **Long-term resilience remains unverified.**
   Stress testing, endurance testing, reconnect cycling and memory-fragmentation
   behavior have not been fully characterized.

## Hardware

The validated controller is an **ESP32-WROOM-32D dev kit** with 4 MB flash
and no PSRAM. Other hardware configurations were not tested in this work.

WoL requires the target PC to be connected by Ethernet. Most WiFi NICs do not
support Wake-on-LAN magic packets.

## Quick Start: Windows PowerShell

**Important:** For the changes documented here, use this modified repository,
not a fresh copy of upstream. The setup scripts can regenerate/remove local
`sdkconfig`; back it up first and do not rerun provisioning blindly on a
previously enrolled device. Never commit `sdkconfig`, device keys or flash dumps.

Windows users should use the native PowerShell setup script. It checks for
ESP-IDF, installs Espressif EIM CLI with `winget` when possible, installs the
preferred ESP-IDF version, prompts for project settings, builds, and flashes.

From the **root of this modified clone** (not a fresh upstream checkout):

```powershell
.\scripts\setup.ps1
```

The script uses Windows COM ports, such as `COM3`, and lists detected serial
ports when possible.

If Windows blocks script execution, run this once in the same PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup.ps1
```

The Windows setup uses Espressif's official installer tooling instead of a
custom GUI. Espressif documents the Windows installer and PowerShell/CMD
environment flow here:

https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/windows-setup.html

## Quick Start: Linux

Linux users should use the Bash setup script:

From the root of the modified clone:

```bash
bash scripts/setup.sh
```

The Linux script looks for ESP-IDF `v5.5.3` under one of these locations:

```text
$IDF_PATH
~/esp/esp-idf
~/esp-idf
/opt/esp-idf
```

If ESP-IDF is missing, the script can clone it from Espressif's upstream source,
checkout `v5.5.3`, run `./install.sh esp32`, and continue. On supported Linux
distributions it can also install common prerequisites with `apt-get`, `dnf`,
`pacman`, or `zypper`.

To choose a different ESP-IDF install location:

```bash
IDF_INSTALL_DIR="$HOME/tools/esp-idf" bash scripts/setup.sh
```

It uses `/dev/ttyUSB0` as the default serial port.

## Configuration

Both setup scripts prompt for the same firmware settings:

| Setting | Default | Description |
| --- | --- | --- |
| `WOL_WIFI_SSID` | none | WiFi network name |
| `WOL_WIFI_PASSWORD` | none | WiFi password |
| `WOL_TAILSCALE_AUTH_KEY` | none | Tailscale auth key |
| `WOL_TARGET_MAC` | none | Target PC Ethernet MAC, such as `AA:BB:CC:DD:EE:FF` |
| `WOL_DEVICE_NAME` | `esp32-wol` | Tailscale device name |
| `WOL_LISTEN_PORT` | `9999` | UDP trigger port |
| `WOL_BROADCAST_IP` | `255.255.255.255` | LAN broadcast address |

You can also change these later with:

```bash
idf.py menuconfig
```

Open `Wake-on-LAN Configuration` in menuconfig.

## Wake Your PC

After flashing, open the serial monitor to find the ESP32's Tailscale IP.

Linux:

```bash
idf.py monitor -p /dev/ttyUSB0
```

Windows:

```powershell
idf.py monitor -p COM3
```

After configuring restrictive tailnet access, send a UDP trigger from an
authorized Tailscale peer. The wake payload is **not** an authentication
secret; do not open the UDP listener to the public Internet:

Set `ESP32_IP` to the device address from the Tailscale administration view,
then send the trigger (never substitute an external/public IP):

```bash
echo wake | nc -u "$ESP32_IP" 9999 -w1
```

The Linux setup script also installs `scripts/wake-pc` to `~/.local/bin`:

```bash
wake-pc --save "$ESP32_IP"
wake-pc
```

## Target PC Setup

In BIOS/UEFI:

- Enable Wake on LAN.
- Disable ErP/EuP Ready if it cuts standby power to the NIC.

On Windows:

- Open Device Manager.
- Open the Ethernet adapter properties.
- Enable `Allow this device to wake the computer`.
- Enable Wake-on-LAN or Magic Packet options if your driver exposes them.

On Linux:

```bash
sudo ethtool -s eth0 wol g
```

## 3D Printed Enclosure

This repo retains an upstream parametric CadQuery enclosure example.
Its dimensions have **not** been verified for the ESP32-WROOM-32D dev kit:

```bash
pip install cadquery
python cad/esp32_enclosure.py
```

Generated STEP files are written to `cad/out/`:

- `esp32_enclosure_base.step`
- `esp32_enclosure_lid.step`
- `esp32_enclosure_assembly.step`

Open the assembly STEP in Fusion 360 to inspect or modify the design. The CAD
script keeps board dimensions, clearances, wall thickness, screw sizing, USB
cutout size, vents, and label text as editable parameters near the top of the
file.

## Troubleshooting

### Bash reports `$'\r': command not found`

The Bash script has Windows CRLF line endings. This repo includes
`.gitattributes` to keep `.sh` files as LF. Re-checkout the repo or run:

```bash
dos2unix scripts/setup.sh scripts/wake-pc
```

On Windows PowerShell, prefer:

```powershell
.\scripts\setup.ps1
```

### `idf.py` is not found on Windows

Run the Windows setup script first:

```powershell
.\scripts\setup.ps1
```

It will try to install Espressif EIM CLI with `winget` and install ESP-IDF
`v5.5.3`. If ESP-IDF was just installed and `idf.py` is still missing, open a
new PowerShell window and run the setup script again.

### Build fails in ESP-IDF `mbedtls`

If the error mentions `mbedcrypto` not being built, the ESP-IDF checkout or
tools install is likely incomplete or stale. Repair ESP-IDF:

```powershell
cd $env:IDF_PATH
git submodule update --init --recursive
.\install.ps1
. .\export.ps1
```

Then rerun:

```powershell
.\scripts\setup.ps1
```

On Linux:

```bash
cd "$IDF_PATH"
git submodule update --init --recursive
./install.sh esp32
source ./export.sh
bash scripts/setup.sh
```

### No COM port is detected on Windows

Reconnect the ESP32, try another USB cable, and check Device Manager. Some
boards need a CP210x or CH340 USB-to-serial driver. You can still type the COM
port manually, such as `COM3`.

### Stale `sdkconfig`

Both setup scripts remove `sdkconfig` and `sdkconfig.old` before building so the
temporary guided configuration is applied cleanly.

## Known Limitations

- DERP-only connectivity is expected for many home networks.
- One ESP32 wakes one configured target MAC.
- Any allowed Tailscale peer can trigger wake unless restricted by Tailscale ACLs.
- The no-PSRAM ESP32 heap is tight; reduce `CONFIG_TS_COORD_BUFFER_SIZE_KB` if needed.

## Attribution and licensing

This is an adaptation of [medinajaime/esp32-wakeonlan](https://github.com/medinajaime/esp32-wakeonlan),
not an independent implementation of the original Tailscale/Wake-on-LAN code.
The upstream README states **MIT**; confirm the applicable repository license
and retain required notices before redistribution. The bundled
[wireguard-lwip](https://github.com/smartalock/wireguard-lwip) component contains
separate **BSD 3-Clause** copyright notices attributed to Daniel Hope;
these must be preserved. See [full attribution](docs/UPSTREAM_ATTRIBUTION.md).
