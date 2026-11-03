# Lab profiles

A profile is `lab/profiles/<name>.yaml`: a list of VMs (name, base_image, vcpu, ssh_user), all on one isolated network. Names and `ssh_user` match `^[a-z0-9-]+$`. RAM is fixed at 4096 MB per VM.

| Profile | VMs | Used by |
| --- | --- | --- |
| `ubuntu-single` | one `ubuntu-2404` VM | T010, T011, T015, T020, T022, T023, T028 |
| `ubuntu-pair` | `server` and `client` (attacks the server), both `ubuntu-2404` | T024, T025, T026, T027 |

Planned, created by their own task: `linux-matrix` (T012), `windows-domain` (T013), `attack-linux` (T014).
