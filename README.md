# Sentinel Validator

A Python test harness for validating Project Sentinel’s intrusion-detection behavior in an **isolated, authorized lab**.

## Test scenarios

The validator provides Scapy-based scenarios for TCP Xmas packets, oversized ICMP payloads, and configurable TCP SYN packets. Use these only against systems you own or have explicit permission to test.

## Requirements

- Python
- Scapy
- On Windows, Npcap may be required for packet operations.

Install Scapy:

```powershell
python -m pip install scapy
```

## Configuration

Create or update `config.py` with the settings used by the scenarios:

- `TARGET_IP` — IP address of the lab target
- `TARGET_PORT` — target TCP port
- `PACKET_COUNT` — number of SYN packets for the test

Keep the target on a dedicated lab network. Do not use public or production systems.

## Run

From the project directory:

```powershell
python main.py
```

Use the project’s actual entry-point filename if it differs from `main.py`. Run with the permissions required by your lab environment, and keep packet counts conservative.

## Safety

- Use an isolated virtual network and authorized test targets only.
- Do not configure public or production IP addresses.
- Keep credentials and secrets out of source control.
