# Moxa GCloud UDMI Integration

[![License](https://img.shields.io/github/license/MEUIIOT/moxa-gcloud-udmi)](LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/MEUIIOT/moxa-gcloud-udmi)](https://github.com/MEUIIOT/moxa-gcloud-udmi/issues)
[![GitHub forks](https://img.shields.io/github/forks/MEUIIOT/moxa-gcloud-udmi)](https://github.com/MEUIIOT/moxa-gcloud-udmi/network)

## Table of Contents
- [Overview](#overview)
- [Data Integrity Rules](#data-integrity-rules)
- [UDMI Capabilities](#udmi-capabilities)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Site Model Requirements](#site-model-requirements)
- [Running as a Service](#running-as-a-service)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Overview
The **Moxa GCloud UDMI Integration** (`v4.3.1`) runs on Moxa industrial gateways such as the
**UC-8220** (Debian 11, Python 3.9). Moxa `MXcloudgate` polls Modbus RTU energy meters (Schneider
Electric PM5561, PM5111, PM8240) and publishes the raw request/response frames on a local MQTT
broker. This gateway decodes those frames and acts as a **UDMI 1.5** gateway (e.g. `CGW-2`) for the
proxied meters (e.g. `EM-11`..`EM-13`), towards **ClearBlade IoT Core** (`/devices/{id}/...` topics,
JWT authentication) or a **UDMI MQTT broker** (`/r/{registry}/d/{id}/...` topics).

![image](https://github.com/user-attachments/assets/0a59dbb3-8941-408a-9212-7d70b7078d9e)

## Data Integrity Rules
The gateway reports what the devices actually say. The UDMI site model is used for configuration
(which devices and points exist), never as a source of device data:

| Reported value | Source |
| :--- | :--- |
| Meter `serial_no`, `software.firmware`, `hardware.make/model` | Meter identity registers (serial 130 or 117, firmware 1637 or 1717, model 50, manufacturer 70). Until the meter has reported them: the configured `serial_no` (or `unknown`), no firmware, `Schneider Electric` / configured meter `type`. |
| Gateway `serial_no` | Hardware serial (device tree / DMI) if the platform exposes it, otherwise `site_details.serial_no` or `--serial-no`. |
| Gateway `hardware` / `software` | `site_details.hardware` / the running gateway version. The platform model is not detected (the device tree may only name the series): without `site_details.hardware` the gateway reports `Moxa` / `UC8220` and logs a warning. |
| Gateway `localnet` (`ether`, `ipv4`, `ipv6`) | Detected on the host. Site model addresses are only used to choose the right NIC on multi-NIC gateways; an address the host does not have is never reported. Re-detected every 60 s. |
| Meter `localnet.modbus.addr` | The configured serial `port` (e.g. `ttyM0`), if set. |
| Self-enumeration features / points | The features this code implements and every point in the meter's register map. |
| Point values | Only **fresh** readings (newer than `modbus.stale_timeout_sec`) are published; see below. |

Telemetry health:
- A point that has not been read within `modbus.stale_timeout_sec` (default 300 s), that the meter
  reports as **not available** (FLOAT32 NaN or the Schneider integer sentinels), or whose register
  block returns a persistent Modbus exception (0x01-0x04) is reported as `value_state: failure` with
  a `pointset.point.failure` status and is **left out** of `events/pointset`
  (`partial_update: true`). Before the first reading a point is `initializing`. A block error is
  only attributed to points fully inside the failed request that no other request read recently.
- If a meter sends no response for the stale timeout, its `gateway.status` reports
  `gateway.proxy.connect` and `system.operation.operational` becomes `false`. Exception replies
  count as responses (the meter is reachable; only the request is wrong).
- Transient errors (CRC, framing, busy/timeout exceptions) are logged (rate-limited) and only matter
  if they persist long enough for the points to go stale. State changes caused only by telemetry
  health are published at most every 12 s, so a flapping meter cannot flood the cloud.

## UDMI Capabilities
- **State and events** for the gateway and every proxied meter: `state`, `events/system` (logs,
  gateway host `metrics` every `metrics_rate_sec` (default 10 s, 0 disables): `mem_total_mb`,
  `mem_free_mb`, `store_total_mb`, `store_free_mb`, `system_load`), `events/pointset`,
  `events/discovery`.
- **Config handling**: `system.config.receive/parse/apply` logging honouring `min_loglevel`
  (default 300); broken configs set `system.status` and keep `last_config`; configs are applied
  atomically (a failing config changes nothing); unknown fields are tolerated; state blocks mirror
  the config blocks. A `pointset` block without a `points` object means "all readable points";
  an empty `points` object means no points.
- **State publishing**: only on change, at most every 2.1 s (12 s for health-only changes); a state
  the MQTT client did not accept is re-sent, and state is always re-sent after a (re)connect.
  Nothing is published while disconnected.
- **`system.mode` restart** (gateway only): on `restart` the process exits with status **192** and the
  supervisor starts it again; the new process reports `mode: initial`, a newer `last_start` and a
  `restart_count` that is persisted in `state_dir` (it counts every process start). It switches to
  `active` when the config says `active` (or has no mode). `shutdown`/`terminate` are not supported
  and are reported as warnings.
- **Gateway proxying**: attaches the configured proxies, follows `gateway.proxy_ids` changes (ids
  that are not configured locally are reported as `gateway.setup.attach`), validates
  `gateway.target` (family `modbus`, address = configured `port`/unit id, `unitid`) and surfaces
  cloud `errors` topic messages (e.g. attach failures) as `gateway.setup.attach` status. An error
  for a configured proxy clears when that proxy receives its config, when it is removed from
  `proxy_ids`, or when a new MQTT session starts (errors reported on the new session are kept);
  errors for any other target clear after 10 minutes without recurrence.
- **Point references** follow the UDMI Modbus grammar:
  `<function>/<address>[/<quantity>][?type=..&worder=..&border=..]` when the site model gives the unit
  id (`localnet.families.modbus.unitid`, else `gateway.target.unitid`), otherwise prefixed with
  `<unitid>/`; the full form `modbus://<addr>/<unitid>/<function>/<address>[/<quantity>]`; or a bare
  register number. The address is the meter's register number (e.g. `3028`); FC 3/4 only; the type
  must match the register map; `worder=LWF`, `border=LSB` and `scale`/`offset` are rejected because
  they cannot be honoured. Unit conversions (`units` different from the register map) are reported
  as `invalid`. `set_value` (writeback) is not supported and reported as `invalid` (the reading is
  still published); blob updates and alarms are reported as unsupported (each with a status).
- **MQTT**: one paho client (1.x or 2.x) with automatic reconnect (exponential backoff 1-120 s);
  connection failures are logged with the concrete TCP/TLS reason (rate-limited); TLS 1.2+ with
  certificate and hostname verification on every Python version; RS256/ES256 JWTs
  (`jwt_expires_minutes`, 10-1440, default 60) are refreshed before expiry by reconnecting the same
  client, so unacknowledged QoS 1 messages are re-sent.
- **Modbus RTU decoding**: CRC-16 checked on responses and on 8-byte requests (configurable),
  exception responses, FLOAT32 (published as the shortest decimal that maps back to the exact value)/
  FLOAT64, INT16/32/64 (signed/unsigned) and ASCII registers.

## Project Structure
```plaintext
moxa-gcloud-udmi/
├── deploy/moxa-gcloud-udmi.service       # systemd unit (Restart=always, StateDirectory)
├── resources/
│   ├── roots.pem                         # Default CA bundle for the cloud MQTT bridge
│   ├── config-google-gateway.json        # Gateway runtime configuration
│   ├── config-cgw2-example.json          # CGW-2 + EM-11..13 configuration example
│   └── modbus_dbo_maps/                  # Schneider Electric register maps (PM5561, PM5111, PM8240)
├── src/
│   ├── main.py                           # Entry point (exit codes 0 / 1 / 192)
│   └── google_iot_core_gateway/
│       ├── runner.py                     # Process model: worker thread, signals, exit codes
│       ├── errors.py                     # Exit codes and configuration errors
│       ├── gcp_handler.py                # Start-up and main loop
│       ├── gcp_publisher.py              # Cloud / UDMI MQTT client
│       ├── internal_broker_subscriber/   # Local MXcloudgate broker subscriber
│       ├── modbus_gw/                    # Modbus RTU frame decoder
│       ├── udmi_handler/                 # UDMI state, config, events and health engine
│       ├── utils/                        # Config, certificates, JWT, logging, persistent store
│       └── gcp_manager.py                # Legacy Cloud IoT Core provisioning helper (not used by
│                                         # the gateway; needs the retired google-cloud-iot package)
├── tests/                                # pytest suite (unit + live Mosquitto end-to-end)
├── tools/
│   ├── frame_report.py                   # Pre-deployment check of real MXcloudgate traffic
│   └── mxcloudgate_simulator.py          # MXcloudgate frame simulator with fault injection
└── udmi_site_model/                      # Site model templates (see Site Model Requirements)
```

## Installation
Python **3.9+** (including Debian 11 `python3.9` on the UC-8220).

```bash
git clone https://github.com/MEUIIOT/moxa-gcloud-udmi.git
cd moxa-gcloud-udmi
python3 -m pip install -r requirements.txt
```

Tested with Python 3.9 and 3.13, paho-mqtt 1.6.1 and 2.1, PyJWT 2.4 and 2.15, cryptography 3.3.1,
3.3.2 and 50. An installed `cryptography` 3.3.x (Debian 11's `python3-cryptography`, or the one an earlier
version of this gateway installed) is accepted, so pip only adds the pure-Python packages. On the
UC-8220 (armv7l), newer `cryptography` wheels need glibc 2.31+ (Debian 11) and pip 20.3+; otherwise
pip would build from source (Rust). Without internet access on the gateway, download the wheels
elsewhere and install them offline:
```bash
pip download -d wheels --python-version 3.9 --only-binary=:all: \
  "paho-mqtt>=1.6.1,<3" "PyJWT>=2.4.0" "typing_extensions>=4.0"
python3 -m pip install --no-index --find-links wheels -r requirements.txt   # on the gateway
```

On a gateway that still runs an older version, install into a virtual environment that reuses the
installed `cryptography`, so the older version's packages stay exactly as they are (rolling back is
then just starting it again); use `.venv/bin/python` in the commands and in the unit's `ExecStart`:
```bash
python3 -m venv --system-site-packages .venv      # Debian: needs the python3-venv package
.venv/bin/python -m pip install -r requirements.txt
```

Before the first deployment, check the real MXcloudgate traffic (listens only, publishes nothing):
```bash
python3 tools/frame_report.py -c resources/config-google-gateway.json --live 300 --save frames.jsonl
```
It reports CRC validity (whether `modbus.crc_check` can stay `strict`), the polled register blocks,
whether the meter identity registers and all register-map points are polled, "not available"
registers and sample values to compare with the meter display. Exit status 0 means ready.

## Configuration
`resources/config-google-gateway.json` (see `resources/config-cgw2-example.json`):

| Key | Meaning |
| :--- | :--- |
| `internal_broker.*` | Local broker where MXcloudgate publishes (`MXcloudgate` topic). |
| `google_cloud.iot_provider` | `gbos` (ClearBlade / IoT Core topics + JWT) or `mqtt` (UDMI broker). |
| `google_cloud.project_id`, `mqtt_bridge_hostname`, `mqtt_bridge_port`, `enable_tls`, `ca_cert` | Cloud connection. A configured `ca_cert` must exist; the bundled `resources/roots.pem` falls back to the system trust store if missing. |
| `google_cloud.sample_rate_set` | Default `events/pointset` interval (s, default 300) until the config sets `sample_rate_sec`/`sample_limit_sec`. |
| `google_cloud.jwt_expires_minutes` | JWT lifetime (10-1440, default 60). |
| `modbus.stale_timeout_sec` | Freshness limit for readings (default 300). Choose more than 2x the MXcloudgate poll interval. |
| `modbus.crc_check` | `strict` (default) or `off` if your MXcloudgate version does not forward valid CRCs. |
| `site_details.gateway_id`, `serial_no`, `hardware`, `localnet.interface` | Gateway identity fallbacks and preferred NIC. |
| `site_details.proxy_ids.<id>` | `type` (register map), `modbus_slave_id`, optional `port` (e.g. `ttyM0`) and optional fallback `serial_no`. Slave ids must be unique. |
| `environment_setup.udmi_site_model_path`, `resources_path`, `state_dir` | Paths. `state_dir` defaults to systemd's `StateDirectory`, `/var/lib/moxa-gcloud-udmi` or `~/.local/state/moxa-gcloud-udmi`. |

`cloud_region` and `registry_id` from the site model's `cloud_iot_config.json` override the module
config; command-line options override both. Secrets (`mqtt_password`) are redacted in debug logs.
Configuration errors make the process exit with status 1.

Place the gateway private key (`rsa_private.pem` or `ec_private.pem`) in
`udmi_site_model/devices/<gateway_id>/` and register the matching public key in the cloud registry.

## Site Model Requirements
The UDMI sequencer compares what the gateway reports with the site model, so the site model must
describe the real installation:
- **Meters**: `system.serial_no`, `hardware`, `software.firmware` must match what the meter reports.
  Configure MXcloudgate to poll the identity registers (30-89, 130 or 117, 1637 or 1717) as well as
  the measurement registers. `pointset.points` should list every point of the register map (that is
  what self-enumeration returns); refs use the grammar above, e.g. `3/3028/2?type=FLOAT32` with
  `localnet.families.modbus` = `{"addr": "<port>", "unitid": "<slave id>"}`.
- **Gateway**: `localnet.families` must contain only the gateway's real addresses (no `ipv6` unless
  it has a global IPv6 address); `software` must match the running version (`{"firmware": "4.3.1"}`).
  The gateway has no points, so it has no `pointset` block.
- **Features** must equal what the code implements:
  - gateway: `system` (stable), `gateway`, `system.mode`, `enumeration`, `enumeration.families`,
    `enumeration.features` (beta);
  - meters: `system`, `pointset` (stable), `gateway`, `enumeration`, `enumeration.families`,
    `enumeration.features`, `enumeration.pointset` (beta).

The templates in `udmi_site_model/` follow these rules. Their meter identities (serial numbers,
firmware) are the simulator's (`tools/mxcloudgate_simulator.py`) and, like the gateway serial
numbers and addresses, are placeholders to replace with the real values. No device keys are
shipped: generate them per installation (e.g. with the UDMI `bin/keygen` tool); the UDMI registrar
reports the gateways as incomplete until their keys exist.

## Running as a Service
```bash
python3 src/main.py -c resources/config-google-gateway.json
```

For production use the bundled systemd unit; `Restart=always` is required for UDMI restarts, and
the unit keeps retrying every 10 s (also after configuration errors, so the gateway recovers on its
own once the configuration is fixed):
```bash
sudo cp deploy/moxa-gcloud-udmi.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now moxa-gcloud-udmi
journalctl -u moxa-gcloud-udmi -f
```

Exit codes (also for `python3 -m google_iot_core_gateway`): `0` clean shutdown on SIGTERM/SIGINT,
also during start-up once Python has imported the gateway (a signal in the first instants after
launch ends the process directly; systemd counts that as a clean stop too), `1` fatal error, `192`
UDMI restart request. The gateway runs in a worker thread that never receives SIGTERM/SIGINT; the
main thread turns them into a clean stop.

For a local UDMI broker:
```bash
python3 src/main.py -c resources/config-cgw2-example.json \
  -iot-provider mqtt -google-cloud-hostname localhost -google-cloud-port 8883 \
  -udmi-site-model-path /path/to/site_model
```

## Testing
```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
```
The end-to-end tests need the `mosquitto` binary and are skipped without it.

Simulate MXcloudgate traffic for slaves 1-3 (all register-map points plus identity registers),
optionally injecting faults:
```bash
python3 tools/mxcloudgate_simulator.py --host 127.0.0.1 --port 1883 --slaves 1,2,3 --interval 2.0 \
  --na 1:3028 --fail-block 2:3000
```

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-improvement`).
3. Ensure `python3 -m pytest` passes and the UDMI registrar validates `udmi_site_model/`.
4. Submit a pull request.

## License
This project is licensed under the GPLv3.0 License - see the [LICENSE](LICENSE) file for details.

## Contact
Moxa Europe GmbH - meuiiot@moxa.com
