# Moxa GCloud UDMI Integration

[![License](https://img.shields.io/github/license/MEUIIOT/moxa-gcloud-udmi)](LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/MEUIIOT/moxa-gcloud-udmi)](https://github.com/MEUIIOT/moxa-gcloud-udmi/issues)
[![GitHub forks](https://img.shields.io/github/forks/MEUIIOT/moxa-gcloud-udmi)](https://github.com/MEUIIOT/moxa-gcloud-udmi/network)

## Table of Contents
- [Overview](#overview)
- [Key Capabilities (UDMI 1.5.2+)](#key-capabilities-udmi-152)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration & CGW-2 Site Model](#configuration--cgw-2-site-model)
- [Usage](#usage)
- [Local Testing & UDMI Sequencer Verification](#local-testing--udmi-sequencer-verification)
- [Contributing](#contributing)
- [License](#license)

## Overview
The **Moxa GCloud UDMI Integration** (`v4.2.0`) bridges Moxa industrial edge gateways (such as the **Moxa UC-8220** running `MXcloudgate`) with **ClearBlade IoT Core**, **Google Cloud IoT Core**, or **local UDMI MQTT reflectors** (`//mqtt/...`) using the **UDMI (Unified Device Management Interface) 1.5.2+** specification.

![image](https://github.com/user-attachments/assets/0a59dbb3-8941-408a-9212-7d70b7078d9e)

## Key Capabilities (UDMI 1.5.2+)
- **First-Class Gateway & Proxied Device Lifecycle:** Publishes schema-valid UDMI `state`, `events/system`, `events/discovery`, and `events/pointset` for **both** the logical gateway (`CGW-2` / `CGW-1`) and all proxied Schneider Electric Modbus RTU energy meters (`EM-11`..`EM-13`, `PM5561`, `PM5111`, `PM8240`).
- **System Mode & Self-Enumeration (`system.mode` & `enumeration.*`):**
  - Supports UDMI `system.operation.mode` transitions (`"restart"` -> `"initial"` -> `"active"`), incrementing `restart_count` and advancing `last_start` (`system_mode_restart`).
  - Supports UDMI `discovery` self-enumeration (`enumerate_nothing`, `enumerate_pointset`, `enumerate_features`, `enumerate_families`, `enumerate_multi`), synchronizing `state.discovery.generation` and publishing schema-valid `events/discovery` payloads.
- **Full Downlink `config` Synchronization:** Subscribes to `/devices/{id}/config` (and `/r/{reg}/d/{id}/config` in local `mqtt` reflector mode) for the gateway and every attached proxy device:
  - Echoes `config.timestamp` to `state.system.last_config` and maintains strict config-to-state **Subblock Parity** (`system`, `gateway`, `pointset`, `localnet`, `discovery`, `blobset`, `alarmset`).
  - Handles malformed JSON configs (`broken_config`): logs `system.config.receive` (`100`) and `system.config.parse` (`500`), suppresses `system.config.apply`, sets `state.system.status` (`category: "system.config.parse"`, `level: 500`), and preserves the last valid `last_config`.
  - Honors `system.min_loglevel` across `receive` (`100`), `parse` (`100`/`500`), and `apply` (`300`), and emits periodic `events/system` host `metrics` (`mem_total_mb`, `mem_free_mb`, `store_total_mb`, `store_free_mb`, `load_average`) when `metrics_rate_sec > 0`.
  - Ignores unknown out-of-schema config fields (`extra_config`) without failing.
- **Dirty-Only Throttled State Updates:** Publishes `state` only when state content changes (after an initial config holdoff and `>2s` minimum spacing), passing `too_much_state` and strict intermediate state validation.
- **Dynamic Pointset & Sampling Control:**
  - Supports per-device `sample_rate_sec` and `sample_limit_sec` (e.g. `pointset_publish_interval` narrow windows), empty gateway pointsets (`points: {}`), dynamic point removal (`pointset_remove_point`), unknown point error reporting (`pointset.point.invalid` at `500`), and invalid `ref` error reporting (`pointset.point.failure` at `500`).
  - Supports both UDMI 1.5 canonical `ModbusFamilyProvider` point references (`[modbus://<addr>/][<unitid>/]<fc>/<reg>[/<qty>][?type=...]`, e.g. `3/3028/2?type=FLOAT32`) and legacy register addresses (`3028`).
  - Filters `NaN`/`Inf`/unread Modbus values out of `events/pointset` so numerical points are strictly JSON numbers (`pointset_numeric_values`).
- **Gateway & Localnet Discovery:**
  - Discovers real Linux host NIC addresses (`ether`, `ipv4`, `ipv6`) on the gateway (`family_ether_addr`, `family_ipv4_addr`, `family_ipv6_addr`) with multi-NIC (`eth0`/`eth1`) matching, while isolating proxied devices' `state.localnet.families` to their own fieldbus family (`modbus`).
  - Validates proxied `config.gateway.target` (`bad_target_family`, `bad_target_address` -> `gateway.proxy.target` at `500`) and dynamically syncs `config.gateway.proxy_ids` (`attach`/`detach`).
- **Hardened Modbus RTU Decoder & MQTT Transport:**
  - Validates Modbus RTU CRC-16 (`0xA001`), detects Modbus exception responses (`fc | 0x80`), supports odd & multi-register numeric/ASCII formats (`float32`, `float64`, `int64`, `int32u`, `int16u`, `str40`), and supports Python **3.9–3.13+** with both `paho-mqtt` **1.x and 2.x** (`RS256` and `ES256` JWTs).

## Project Structure
```plaintext
moxa-gcloud-udmi/
├── resources/
│   ├── certs/roots.pem                   # Google / ClearBlade TLS Root CAs
│   ├── config-google-gateway.json        # Gateway runtime configuration (CGW-2 default)
│   ├── config-cgw2-example.json          # Annotated CGW-2 + EM-11..13 configuration example
│   └── modbus_dbo_maps/                  # Schneider Electric register maps (PM5561, PM5111, PM8240)
├── src/
│   ├── main.py                           # Gateway CLI entry point
│   ├── app_data.py                       # Runtime thread state holder
│   └── google_iot_core_gateway/
│       ├── gcp_handler.py                # Main event loop (Modbus queue, downlink configs, UDMI publish)
│       ├── gcp_publisher.py              # Cloud IoT / ClearBlade (`/devices/...`) & local UDMI (`/r/...`) MQTT client
│       ├── gcp_manager.py                # Cloud IoT registry/device provisioning helper
│       ├── internal_broker_subscriber/   # Internal Mosquitto subscriber (`MXcloudgate` RTU frames)
│       ├── modbus_gw/                    # CRC-16 validated Modbus RTU -> JSON register decoder
│       ├── udmi_handler/                 # UDMI 1.5.2+ state, config, system event & pointset engine
│       └── utils/                        # Config, certificate (RSA/EC), JWT & logging utilities
├── tests/
│   └── test_udmi_sequencer_compliance.py # Unit & live-Mosquitto end-to-end compliance tests
├── tools/
│   └── mxcloudgate_simulator.py          # Synthetic MXcloudgate Modbus RTU publisher (slaves 1, 2, 3)
└── udmi_site_model/                      # Clean UDMI 1.5.2 site model templates (CGW-2/EM-11..13 & CGW-1/EM-1..3)
```

## Installation
Compatible with **Python 3.9–3.13+** (including Debian 11 `python3.9` on Moxa UC-8220).

```bash
git clone https://github.com/MEUIIOT/moxa-gcloud-udmi.git
cd moxa-gcloud-udmi
python3 -m pip install -r requirements.txt
```

## Configuration & CGW-2 Site Model
1. **Gateway Configuration (`resources/config-google-gateway.json`):**
   Configure `internal_broker` (host/port of the local `MXcloudgate` broker), `google_cloud` (`iot_provider`: `"gbos"` for ClearBlade/GCP IoT Core or `"mqtt"` for a local UDMI reflector broker, `project_id`, `cloud_region`, `mqtt_bridge_hostname`), `site_details` (`gateway_id: "CGW-2"`, `serial_no`, and `proxy_ids` mapping `EM-11` -> slave `1` `PM5561`, `EM-12` -> slave `2` `PM5111`, `EM-13` -> slave `3` `PM8240`), and `environment_setup.udmi_site_model_path`.
2. **UDMI 1.5.2 Site Model (`udmi_site_model/`):**
   - Ready-to-use `Registrar`-validated templates are provided under `udmi_site_model/devices/CGW-2` and `udmi_site_model/devices/EM-11..13` (as well as `CGW-1` and `EM-1..3`).
   - **Important for UDMI Sequencer runs on `CGW-2`:** If your site model previously had `"testing": {"nostate": true}` on `CGW-2` or `EM-11..13` from older v4.1.x deployments, remove `"nostate": true` so the UDMI Sequencer enables all `state`-dependent sequences (`system_last_update`, `broken_config`, `extra_config`, `state_make_model`, `state_software`, `too_much_state`, `family_*_addr`, `gateway_proxy_state`, `pointset_remove_point`, `pointset_request_extraneous`, `bad_target_*`, `bad_point_ref`).
   - Place the gateway private key (`rsa_private.pem` / `rsa_private.pkcs8` or `ec_private.pem`) in `udmi_site_model/devices/CGW-2/` and register the corresponding public key in ClearBlade / UDMIS.

## Usage
### Running the Gateway
```bash
python3 src/main.py -c resources/config-google-gateway.json
```

Useful CLI overrides:
```bash
python3 src/main.py \
  -c resources/config-cgw2-example.json \
  -iot-provider gbos \
  -google-cloud-project-id <PROJECT_ID> \
  -google-cloud-hostname europe-west1-mqtt.clearblade.com \
  -site-details-registry-id UK-LON-GLAB \
  -site-details-gateway-id CGW-2 \
  -serial-no CGW2-UC8220-001 \
  -v 3
```

For local UDMI MQTT reflector testing (`//mqtt/localhost`):
```bash
python3 src/main.py \
  -c resources/config-cgw2-example.json \
  -iot-provider mqtt \
  -google-cloud-hostname localhost \
  -google-cloud-port 8883 \
  -udmi-site-model-path /path/to/site_model
```

## Local Testing & UDMI Sequencer Verification
Run the automated compliance & end-to-end test suite:
```bash
pytest
```

To simulate Moxa `MXcloudgate` Modbus RTU traffic locally against a Mosquitto broker for `EM-11` (slave 1), `EM-12` (slave 2), and `EM-13` (slave 3):
```bash
python3 tools/mxcloudgate_simulator.py --host 127.0.0.1 --port 1883 --slaves 1,2,3 --interval 2.0
```

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-improvement`).
3. Ensure `pytest` passes and UDMI `registrar` reports `"CLEAN"` on `udmi_site_model/`.
4. Submit a pull request.

## License
This project is licensed under the GPLv3.0 License - see the [LICENSE](LICENSE) file for details.

## Contact
Moxa Europe GmbH - meuiiot@moxa.com
