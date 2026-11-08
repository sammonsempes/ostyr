# Lab profiles

A profile is `lab/profiles/<name>.yaml`: a list of VMs (name, base_image, vcpu, ssh_user), all on one isolated network. Names and `ssh_user` match `^[a-z0-9-]+$`. Optional per-VM fields: `guest` (`linux` default, or `windows`), `firmware` (`bios` default, or `uefi` with OVMF Secure Boot), `tpm` (`true` adds a swtpm TPM 2.0), `memory_gb` (`4` default, or `8`) and `disk_gb` (overlay size, default 20). The quota counts each started 4 GB of RAM as one unit against `LAB_MAX_VMS`. A profile may have a `<name>.setup.sh` that `up.sh` runs from the host once every VM answers SSH, with the lab state directory and the lab prefix as arguments.

| Profile | VMs | Used by |
| --- | --- | --- |
| `ubuntu-single` | one `ubuntu-2404` VM | T010, T011, T015, T020, T022, T023, T028 |
| `ubuntu-pair` | `server` and `client` (attacks the server), both `ubuntu-2404` | T024, T025, T026, T027 |
| `linux-matrix` | `ubuntu` (`ubuntu-2404`), `rocky9` (`rocky-9`), `rocky8` (`rocky-8`, kernel 4.18), `debian` (`debian-12`) | T012 |
| `windows-domain` | `dc` (`ws2022-dc`, 4 GB) promotes `lab.ostyr.test`; `ws` (`win11`, 8 GB) joins it; 3 quota units | T013 |
| `oidc-pair` | `server` (`ubuntu-2404`) and `zitadel` (`zitadel`: Zitadel + PostgreSQL, TLS from a per-lab CA); `OIDC_REDIRECT_URI` sets the application redirect URI | T016, T026B |
| `attack-linux` | `attacker` (`attacker`: Atomic Red Team, egress confined to the lab subnet) and `target` (`ubuntu-2404`) | T014, T030 |
| `datastore-pair` | `datastore` (`datastore`: ClickHouse, NATS JetStream, PostgreSQL, TLS from a per-lab CA, credentials in `/etc/ostyr-lab/datastore.env`) and `client` (`ubuntu-2404` with the nats CLI and psql installed by the setup script) | T018 |

The `k3s-node` and `backup-server` images have no profile yet; a task that needs them adds its own.
