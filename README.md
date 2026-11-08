# Ostyr

Open source IT and security platform in Rust: monitoring, RMM, EDR, SIEM, response, identity, WAF, DNS. Modular, everything as code, AGPL-3.0.

## What it is

Ostyr is an IT platform, not only a cyber one: it monitors and manages the estate (Windows, Linux, macOS and mobile devices) and detects and responds to threats.

- Modular: each module runs alone or combined with the others, and none depends on another to start.
- Local, deterministic blocking: protection never depends on AI, the server or the network.
- AI under guardrails: investigation and tuning are assisted by AI, bounded by a deterministic validator, circuit breakers and a full history. The default mode is human approval.
- Everything as code: deployment, configuration, rules, policies and playbooks live in Git and roll back from Git. There is no no-code editor.

## Modules

EDR, SIEM and detection, response and cases, AI, identity provider, GRC, WAF, DNS, DHCP, NDR, RMM, CMDB, monitoring, on-call, status page, site collector, vulnerability and compliance, MDM.

No listening port is ever opened on a managed device: every flow is initiated by the device. Ostyr's own interface is the only UI; no third-party component exposes one.

## Status

Early development. Nothing is packaged or released yet. The workspace holds these crates in `crates/`:

| Crate | Role |
| --- | --- |
| `agent-channel` | gRPC channel between the endpoint agents and the management server over mutual TLS 1.3 |
| `agent-command` | Signed, anti-replay command envelope for the endpoint agent |
| `cases` | Case management data model and pure rules: transitions, SLA, templates, shared observables |
| `cmdb` | Pure CMDB asset model, declared business attributes, reconciliation and impact query |
| `core-api` | REST API skeleton every module mounts its routes on |
| `core-audit` | Append-only, hash-chained audit log shared by every module |
| `core-auth` | Local authentication, MFA, sessions and RBAC shared by every module |
| `core-config` | Strict loading of the declarative YAML configuration |
| `core-export` | ECS event export to syslog and webhook |
| `core-redact` | Secret redaction shared by the audit log, the structured logs and the ECS export |
| `dns-rpz` | RPZ zone generation from normalised threat intelligence IOCs |
| `ecs-normalise` | Tetragon JSON events normalised to ECS and the Sigma Linux categories |
| `intel-feeds` | Threat intelligence feed parsing into a normalised IOC model |
| `response-breakers` | Global circuit breakers every playbook action passes through |
| `response-playbooks` | Playbook parsing, validation and simulation; nothing here executes an action |
| `siem-schema` | ClickHouse table schema for ECS events, generated as code |
| `sigma-sql` | Single-event Sigma rules compiled to ClickHouse SQL over ECS events |
| `stream-correlation` | Sigma correlation rules over a stream of ECS events, with persistent windows |
| `xdrctl` | Command line client of the REST API |

`tools/` holds the development tools `custom_lint` and `coverage_gate`.

## Build and test

```sh
cargo build
cargo test
```

Before each commit, `.githooks/pre-commit` runs the full gate: `cargo +nightly fmt --check`, `cargo clippy --all-targets -- -D warnings`, `custom_lint`, `cargo +nightly llvm-cov --branch --fail-under-lines 100` and `coverage_gate`. Enable it with `git config core.hooksPath .githooks`.

## Licence

AGPL-3.0-only, see [LICENSE](LICENSE). The specification is in [docs/spec.md](docs/spec.md).
