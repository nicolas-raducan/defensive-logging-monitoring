# Phase 1 — Splunk Indexer Setup

The SIEM's collection point: a Splunk Enterprise (Free tier) instance on an
Ubuntu Server VM. It receives endpoint telemetry from the Windows domain and is
the search head for all detections.

> **Environment note:** This SIEM monitors an existing Active Directory lab
> (see the [enterprise-zero-trust-ad](https://github.com/nicolas-raducan/Enterprise-Zero-Trust-AD)
> project). The Windows endpoint forwarding data in Phase 2 is one of that lab's
> managed Win10 VMs. This repo covers the monitoring layer only.

## Host

| | |
|---|---|
| Platform | virt-manager / KVM |
| Guest | Ubuntu Server 24.04 (text installer) |
| Resources | 4 GB RAM · 2 vCPU · 25 GB disk |
| Splunk | Enterprise 10.4.0 (Free tier, ≤500 MB/day) |
| Install path | `/opt/splunk`, run as non-root user `splunk-svc` |
| Desktop | `xubuntu-desktop` layered on the Server base (optional, for local GUI) |

> **Why Server ISO, not Desktop ISO:** the 24.04 Desktop live ISO would not
> render its installer under virt-manager (graphics-stack failure). The Server
> ISO's text installer has no graphics dependency. A desktop was then added on
> top — see *Adding a desktop* below.

## Steps

1. **Install Splunk** from the `.deb` to `/opt/splunk`.
2. **Hand ownership to a dedicated runtime user** (the `.deb` installs as root;
   running Splunk 10.x as root is deprecated), then put Splunk on `PATH`
   (`SPLUNK_HOME` alone does not do this):
   ```bash
   sudo chown -R splunk-svc:splunk-svc /opt/splunk
   # as the splunk-svc user:
   echo 'export PATH=$PATH:/opt/splunk/bin' >> ~/.bashrc && source ~/.bashrc
   ```

> From here run every `splunk` command **as `splunk-svc`, without `sudo`** —
> ownership now belongs to that user. Only the firewall rule and `boot-start`
> need root (and `boot-start` runs as root, so it uses the full path because
> root's `PATH` has no Splunk).

3. **First start** (accept licence non-interactively, then set admin creds):
   ```bash
   splunk start --accept-license
   ```
4. **Enable boot persistence** (needs root — writes a systemd unit):
   ```bash
   sudo /opt/splunk/bin/splunk enable boot-start -user splunk-svc
   systemctl is-enabled splunk   # -> "generated"
   ```
5. **Enable the forwarder receiving port (9997):**
   ```bash
   splunk enable listen 9997 -auth admin:<pw>
   sudo ufw allow 9997/tcp        # firewall change needs root
   ```
6. **Create the `endpoint` index** to isolate Windows telemetry from Splunk's
   internal logs:
   ```bash
   splunk add index endpoint
   ```

## Verification

- Web UI loads at `http://10.0.0.100:8000` with no startup errors.
- Receiving port is listening:
  ```bash
  splunk display listen
  ```
- `endpoint` index exists:
  ```bash
  splunk list index | grep endpoint
  ```

## Adding a desktop (optional)

A GUI was layered onto the running Server base and installed cleanly:

```bash
sudo apt update && sudo apt install xubuntu-desktop
```

> **Why this is worth noting:** the Desktop *live ISO* black-screened during
> install, but the desktop *packages* install fine on top of a working Server
> system. A failed graphical **installer** is not the same as the guest being
> unable to run a desktop — the failure was specific to the live ISO's
> installer environment, not the XFCE stack.

## Issues encountered and fixes

- **`dpkg -i` → `No space left on device`.** Ubuntu Server's guided LVM install
  allocated only part of the 25 GB disk to root, leaving the rest as unused free
  space in the volume group. Fixed by extending root into it:
  ```bash
  sudo lvextend -r -l +100%FREE /dev/<vg>/<root-lv>
  ```
- **`splunk: command not found`.** `SPLUNK_HOME` doesn't add Splunk to `PATH` —
  the binary is at `/opt/splunk/bin`. Add it to `PATH` or call the full path.
- **Permission / root errors on first start.** Caused by the root-owned install +
  deprecated root execution. Fixed by step 2 (chown) and running as `splunk-svc`.
- **Desktop live ISO black-screens under virt-manager** — see *Why Server ISO*
  and *Adding a desktop*.

## Result

Splunk indexer running, persistent across reboot, listening on 9997, with a
dedicated `endpoint` index ready for Windows telemetry.

→ **Next:** [Phase 2 — Endpoint Telemetry Pipeline](02-endpoint-pipeline.md)
