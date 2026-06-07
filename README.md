# Defensive Logging & Monitoring (Splunk SIEM & Detection Engineering Lab)

## Context & Motivation

This repository layers a **SIEM and detection-engineering capability** on top of
an existing enterprise Active Directory environment —
[Enterprise-Zero-Trust-AD](https://github.com/nicolas-raducan/Enterprise-Zero-Trust-AD).
Where that lab *hardens* a Windows domain, this project *watches* it: it
collects endpoint telemetry, centralises it in Splunk, and authors custom
detections mapped to the **MITRE ATT&CK** framework.

The motivation is to close the single biggest hands-on gap for a SOC Analyst
role: **operating a SIEM against real endpoint data** — onboarding logs,
writing SPL, and turning raw telemetry into threshold-based alerts that fire on
attacker behaviour rather than on signatures.

> **Project status (June 2026):** Phase 1 (Splunk indexer) is complete. Phase 2
> (endpoint telemetry pipeline) is in progress. Phases 3–4 (detection authoring
> and ATT&CK write-up) are planned. Each section below is marked with its
> current state.

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Detection Model](#detection-model)
4. [Technologies & Core Concepts](#technologies--core-concepts)
5. [Repository Structure](#repository-structure)
6. [System Requirements](#system-requirements)
7. [Installation & Setup Guide](#installation--setup-guide)
8. [Key Implementation Features](#key-implementation-features)
9. [Validation & Test Scenarios](#validation--test-scenarios)
10. [Engineering Lessons](#engineering-lessons)

## Project Overview

A SIEM pipeline built around **Splunk Enterprise (Free tier)** running headless
on an Ubuntu Server VM as the indexer and search head. A Windows 10 endpoint
(one of the AllSafeCorp domain's managed VMs) runs **Sysmon** for high-fidelity
process/network telemetry and a **Splunk Universal Forwarder** that ships both
Sysmon and Windows Security events to the indexer. Custom **SPL** detections then
identify credential-attack activity and are mapped to **MITRE ATT&CK** techniques.

## Architecture

Telemetry flows one way from the monitored endpoint to the indexer; an attacker
VM generates the activity the detections are designed to catch.

```mermaid
graph LR
    Parrot[Parrot OS Attacker<br/>Hydra brute-force] -->|RDP / SMB| Win10

    subgraph Domain [AllSafeCorp Domain - KVM/QEMU]
        Win10[Win10 Endpoint<br/>Sysmon + Universal Forwarder]
    end

    Win10 -->|TCP 9997<br/>forwarded events| Splunk

    subgraph Indexer [Ubuntu Server VM]
        Splunk[Splunk Enterprise<br/>index = endpoint<br/>SPL detections + alerts]
    end

    classDef attacker fill:#ffe6e6,stroke:#ff0000,stroke-width:2px;
    classDef siem fill:#e6f3ff,stroke:#0066cc,stroke-width:2px;
    class Parrot attacker;
    class Splunk siem;
```

## Detection Model

Each detection turns a raw telemetry source into a behavioural alert and maps it
to the technique it catches.

| Detection | Telemetry source | Detection logic | MITRE ATT&CK | Status |
|---|---|---|---|---|
| **Brute-force login** | Windows Security (4625 / 4624) | At least 10 failed logons from one source/user within 5 min; flag a 4624 success *after* the failures (spray-then-succeed) | T1110, T1110.001, T1110.003 | Planned (Phase 3) |
| **LSASS credential access** | Sysmon (Event ID 10) | Process access handle opened against `lsass.exe` | T1003.001 | Stretch |
| **PsExec lateral movement** | Sysmon (Event ID 1 + 3) | Service-style process creation paired with SMB (445) network connection | T1021.002 | Stretch |

## Technologies & Core Concepts

* **SIEM & Data Onboarding:** Splunk Enterprise (Free tier) — indexer, search head, dedicated `endpoint` index, TCP receiving input on 9997.
* **Endpoint Telemetry:** Sysmon (SwiftOnSecurity community config), Splunk Universal Forwarder, Windows Security event log.
* **Detection Engineering:** SPL (`stats`, `where`, `bin`, `eval`), threshold-based scheduled alerts.
* **Threat Mapping:** MITRE ATT&CK (Credential Access, Lateral Movement).
* **Virtualization:** KVM/QEMU, `libvirt`, `virt-manager` (shared with the AD lab environment).

## Repository Structure

* `docs/`: Per-phase build notes and the full command/troubleshooting reference.
    * `01-splunk-setup.md`: Phase 1 — Splunk indexer install, hardening, gotchas.
    * `02-endpoint-pipeline.md`: Phase 2 — Sysmon + forwarder onboarding *(in progress)*.
* `configs/`: Sanitized `inputs.conf` / `outputs.conf` from the forwarder.
* `detections/`: Saved SPL queries / alert definitions.
* `screenshots/`: Visual proof of the pipeline and triggered alerts.

> All configs are **sanitized** — IPs, hostnames, and credentials are replaced
> with placeholders such as `<INDEXER_IP>`.

## System Requirements

**Hosts (all virtualized on the existing KVM/QEMU lab host):**
* **Splunk indexer:** Ubuntu Server 24.04 — 4 GB RAM, 2 vCPU, 25 GB disk.
* **Monitored endpoint:** Windows 10 — a managed Tier 2 VM from the AD lab.
* **Attacker:** Parrot OS — used in Phase 3 to generate brute-force telemetry.

**Software:**
* Splunk Enterprise Free (≤ 500 MB/day) and the matching Universal Forwarder.
* Sysmon + the SwiftOnSecurity `sysmonconfig-export.xml`.

## Installation & Setup Guide

### Phase 1 — Splunk Indexer (complete)

On the Ubuntu Server VM (full commands and troubleshooting in
[`docs/01-splunk-setup.md`](docs/01-splunk-setup.md)):

```bash
# install the .deb to /opt/splunk, hand it to a non-root runtime user, add to PATH
sudo chown -R splunk-svc:splunk-svc /opt/splunk
echo 'export PATH=$PATH:/opt/splunk/bin' >> ~/.bashrc && source ~/.bashrc

# run as splunk-svc, no sudo: start, enable the receiving port, create the index
splunk start --accept-license
splunk enable listen 9997 -auth admin:<pw>
splunk add index endpoint

# these two need root: boot persistence (writes a systemd unit) and the firewall
sudo /opt/splunk/bin/splunk enable boot-start -user splunk-svc
sudo ufw allow 9997/tcp
```

### Phase 2 — Endpoint Telemetry Pipeline (in progress)

On the Windows 10 endpoint:

```powershell
# 1. install Sysmon with the community config (elevated prompt)
.\sysmon64.exe -accepteula -i sysmonconfig-export.xml

# 2. install the Universal Forwarder, point it at the indexer
.\splunk.exe add forward-server <INDEXER_IP>:9997
```

Then collect both logs via `inputs.conf` and ship them via `outputs.conf`
(see [`configs/`](configs/)):

```ini
[WinEventLog://Security]
index = endpoint
disabled = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = endpoint
disabled = 0
renderXml = true
```

**Acceptance check** — in Splunk, both sourcetypes appear:

```spl
index=endpoint | stats count by sourcetype
```

### Phase 3 — Brute-Force Detection (planned)

Run Hydra from Parrot OS against the endpoint's SMB/RDP to generate failed logons,
then author and schedule the SPL alert from the [Detection Model](#detection-model).

### Phase 4 — ATT&CK Mapping & Write-up (planned)

Map the firing detection to MITRE ATT&CK and complete this documentation.

## Key Implementation Features

### 1. Isolated telemetry index
Windows endpoint data lands in a dedicated `endpoint` index, kept separate from
Splunk's internal logs — cleaner searches and a clear data-retention boundary.

### 2. Community-standard Sysmon baseline
Rather than hand-writing a Sysmon config, the project deploys the
**SwiftOnSecurity** baseline — the recognised community standard — demonstrating
the judgement to adopt and version a vetted config over reinventing one.

### 3. Behavioural, threshold-based detection
The brute-force detection alerts on a *rate of failures* and the
*spray-then-succeed* pattern (failures followed by a success), not on any single
event — detection logic grounded in attacker behaviour.

### 4. Secure-by-default operation
Splunk runs as a dedicated non-root user (root execution is deprecated in 10.x),
and email-alert delivery is restricted to an allow-listed domain to prevent
search results being exfiltrated to arbitrary recipients.

## Validation & Test Scenarios

*Phase 1 (current):* Splunk web UI loads with no startup errors and the receiving
port is listening (`splunk display listen`); the `endpoint` index exists.

*Phases 2–3 (pending):* screenshots of both sourcetypes arriving in
`index=endpoint`, and of the brute-force alert appearing under
*Activity → Triggered Alerts*, will be added here as those phases complete.

## Engineering Lessons

* **A failed graphical *installer* ≠ an unusable desktop.** The Ubuntu 24.04
  Desktop *live ISO* black-screened under virt-manager, so the indexer was built
  from the Server ISO's text installer. Installing `xubuntu-desktop` on top of
  the running Server base afterwards worked cleanly — proving the failure was
  specific to the live ISO's installer environment, not the desktop packages.
* **Subiquity's guided LVM under-allocates root.** The installer left part of the
  25 GB disk as unused free space in the volume group, surfacing as
  `No space left on device` during install; fixed by extending the root LV
  (`lvextend -r -l +100%FREE`).
* **Splunk 10.x ownership model.** The `.deb` installs as root, but running
  Splunk as root is deprecated — ownership had to be handed to a dedicated
  service user, and `/opt/splunk/bin` added to `PATH` (`SPLUNK_HOME` does not do
  this).
