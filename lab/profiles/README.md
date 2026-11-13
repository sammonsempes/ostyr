# Lab profiles

A profile is `lab/profiles/<name>.yaml`: a list of VMs (name, base_image, vcpu, ssh_user), all on one isolated network. Names and `ssh_user` match `^[a-z0-9-]+$`. Optional per-VM fields: `guest` (`linux` default, or `windows`), `firmware` (`bios` default, or `uefi` with OVMF Secure Boot), `tpm` (`true` adds a swtpm TPM 2.0), `memory_gb` (`4` default, or `8`) and `disk_gb` (overlay size, default 20). The quota counts each started 4 GB of RAM as one unit against `LAB_MAX_VMS`. A profile may set a top-level `egress: proxy` (default `none`): `up.sh` then starts the allowlist proxy of `lab/egress-allow.txt` on the bridge address and configures the VMs to use it; attack profiles must stay `none`. `ubuntu-single` uses `proxy`. A profile may have a `<name>.setup.sh` that `up.sh` runs from the host once every VM answers SSH, with the lab state directory and the lab prefix as arguments.

| Profile | VMs | Used by |
| --- | --- | --- |
| `ubuntu-single` | one `ubuntu-2404` VM | T010, T011, T015, T020, T022, T023, T028 |
| `rocky-single` | one `rocky-9` VM, `egress: proxy` | T120B |
| `ubuntu-pair` | `server` and `client` (attacks the server), both `ubuntu-2404` | T024, T025, T026, T027 |
| `linux-matrix` | `ubuntu` (`ubuntu-2404`), `rocky9` (`rocky-9`), `rocky8` (`rocky-8`, kernel 4.18), `debian` (`debian-12`) | T012 |
| `windows-domain` | `dc` (`ws2022-dc`, 4 GB) promotes `lab.ostyr.test`; `ws` (`win11`, 8 GB) joins it; 3 quota units | T013 |
| `oidc-pair` | `server` (`ubuntu-2404`) and `zitadel` (`zitadel`: Zitadel + PostgreSQL, TLS from a per-lab CA); `OIDC_REDIRECT_URI` sets the application redirect URI | T016, T026B |
| `attack-linux` | `attacker` (`attacker`: Atomic Red Team, egress confined to the lab subnet) and `target` (`ubuntu-2404`) | T014, T030 |
| `datastore-pair` | `datastore` (`datastore`: ClickHouse, NATS JetStream, PostgreSQL, TLS from a per-lab CA, credentials in `/etc/ostyr-lab/datastore.env`) and `client` (`ubuntu-2404` with the nats CLI and psql installed by the setup script) | T018 |
| `e2e-linux` | the `datastore-pair` VMs (`datastore`, `client`); `e2e-linux.setup.sh` also runs the datastore-pair setup, then installs the Ostyr services on `datastore` and Tetragon plus the Linux agent on `client` (tenant `lab`, agent `agent1`); proof `lab/tests/e2e-alert.sh` | T169 |
| `proxmox-single` | one `debian-12` VM `pve` (4 vCPU, 8 GB RAM = 2 quota units, 40 GB disk, `egress: proxy`) running Proxmox VE 8.4 (API 8.4.21 on 2026-11-13) from the no-subscription repository; `proxmox-single.setup.sh` pins the repository key (`images/keys/proxmox-release-bookworm.gpg`, SHA-512 in the `.sha512` file beside it, taken from the Proxmox installation wiki page for Debian 12), ships `proxmox-single.remote.sh`, and creates QEMU definitions 9001 and 9002 (`kvm: 0`) and LXC 9003, none started; the setup tolerates a missing LXC template. API `https://<vm>:8006/api2/json`, node `pve`; tokens `user!lab=secret` in `lab/state/<task>/pve-auditor-token` (user `lab-auditor@pve`, `PVEAuditor`) and `pve-admin-token` (`lab-admin@pve`, `PVEVMAdmin`), mode 600. Setup takes about 65 min under TCG for the whole `up.sh` (measured 4170 s, boot and the `proxmox-ve` install dominate), about 2.5 min when re-run. Proof: `lab/tests/proxmox-single-test.sh` (no VM) | T381 |

The `k3s-node` and `backup-server` images have no profile yet; a task that needs them adds its own.
