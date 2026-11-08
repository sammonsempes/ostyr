# Specification: open source XDR platform (hardened version)

Nov 2, 2026 · @Samsam

## 1. Vision and positioning

An open source cyber platform, usable straight after installation without expert configuration, that detects and blocks locally and deterministically, then investigates and tunes itself with built-in AI. It relies on **ClickHouse** for storage, search and correlation, and on **osquery** for endpoint inventory and querying.

**Differentiation.** Wazuh already covers agents, FIM and active response; Security Onion covers NDR; dedicated tools cover forensics; Shuffle covers SOAR. This project's own value comes down to three points:

- **orchestration of recognised native sensors** (Sysmon, Defender, Tetragon, YARA-X, osquery) rather than a home-made sensor, with continuous checking of their state;
- **automatic, reversible tuning by AI**, framed by a deterministic validator, with a complete history.
- **everything as code and modular**: each module (EDR, WAF, DNS, identity provider…) deploys alone or combined with the others, and all configuration lives in Git, with no no-code interface.

**IT platform scope.** The platform is an IT platform, not only a cyber one: next to detection and response it monitors and manages the estate. It covers host and application metrics (CPU, memory, disk I/O and space, temperature, OOM kills, reboots, system calls through eBPF), network traffic (IDS), HTTP requests and edge attacks (WAF), authentications, logs, threat intel, application health, obsolete versions and vulnerabilities, and it manages devices (scripts, patches, software, remote shell and desktop) on Windows, Linux, macOS and mobile devices. Sections 20 to 23 specify these functions; they follow the same three differentiators and the same component rules (section 4).

Anything that does not serve these three points is either delegated to a connector, shipped as an optional module, or placed out of scope (section 19).

**Target audience.** SMEs and mid-sized companies without a dedicated SOC (main target of v1), in-house SOC teams, and MSSPs thanks to multi-tenancy.

## 2. Guiding principles

- **Operational from installation, without bloat.** Detection rules, threat intel, protection policies, FIM and honeytokens are active by default. A single module installs with one command in under 10 minutes; the "all-in-one" profile in under 30 minutes. Heavy components (NATS JetStream, ClickHouse cluster, local AI) are only required when volume or usage justifies them.
- **Blocking never depends on AI.** Local detection and blocking are deterministic. If the AI, the server or the network is unreachable, the agent keeps protecting with its cached policies.
- **AI is strongly recommended, not blocking.** An AI provider (external API or local model) is offered during installation. Without AI, the platform starts in an explicit **degraded mode**: permanent banner in the interface, manual triage, no automatic tuning. A local model must pass a qualification test before it is enabled (section 8).
- **The human stays in control by default.** The default tuning mode is "human approval". Switching to autonomous mode is an explicit, reversible and logged decision.
- **Limited blast radius.** Every automatic action is bounded by circuit breakers (number of actions per hour, critical assets excluded, simulation available).
- **Build on proven components.** The agent is an orchestrator: it installs, configures, updates and monitors recognised sensors rather than reimplementing everything.
- **Measurable performance.** Resource budgets are quantified (section 3) and checked continuously on every endpoint.
- **Full traceability.** Every change, whether made by a human or by the AI, is recorded, comparable (diff) and reversible.
- **Transparency.** All data, decisions and actions are visible in the interface, including the AI's reasoning.
- **Secure by design.** The platform is treated as a critical asset, with its own threat model (section 12).
- **Strict modularity.** Each module (EDR, SIEM and detection, response and cases, AI, identity provider, GRC, WAF, DNS, DHCP, NDR, RMM, CMDB, monitoring, on-call, status page, site collector, vulnerability and compliance, MDM) and each connector works alone. Combined, they enrich each other, but none depends on another to start (section 4).
- **Everything as code (IaC).** Deployment, configuration, rules, policies, exclusions, playbooks, connectors, roles and frameworks are described in declarative files versioned in Git. A whole platform can be recreated identically from its repository (section 11).
- **API first, no no-code.** Every function is first an API, then a CLI command, then a screen. The interface is for viewing, investigating and approving; it offers no visual editor, and every change it makes becomes a commit.
- **No listening port on a managed device.** Every flow from a managed device is initiated by the device: the agent channel is outbound gRPC over mTLS to the server or a relay (section 4), and remote shell, file transfer and remote desktop travel inside or through outbound connections. No agent opens a listening socket for remote access.
- **Headless components only.** No third-party component with its own graphical interface reaches a user: the interface is Ostyr's alone (section 13). Durable state lives in PostgreSQL, ClickHouse, NATS JetStream, MinIO or Git; a new stateful component needs an owner decision.
- **Easy investigation and readable logs.** An event can be understood without knowing its source: plain-language summary, decoded values, context displayed alongside, one-click pivot to everything related to it. The raw data always remains accessible (section 13).

## 3. Non-functional requirements

The values below are initial targets for v1, to be confirmed by benchmarks before going into production.

| Requirement | v1 target | Measurement |
| --- | --- | --- |
| CPU of the agent and its sensors (excluding antivirus scans) | < 3 % on average, < 10 % peak over 1 min | Agent internal telemetry |
| Agent memory (excluding Defender) | < 300 MB | Agent internal telemetry |
| Local blocking delay (ASR, Tetragon, App Control) | Before the action executes | Atomic Red Team tests |
| Windows reactive kill delay | < 1 s after process creation | Test bench |
| Central detection → alert delay | < 60 s at the 95th percentile | End-to-end timestamps |
| Alert → AI verdict delay | < 5 min at the 95th percentile | End-to-end timestamps |
| Interactive search over 24 h | < 2 s at the 95th percentile | Load bench, typical hunting queries |
| Search over 30 days (hot and warm storage) | < 15 s at the 95th percentile | Load bench |
| Opening an alert with all its context | < 3 s | Measured in the interface |
| Ingestion throughput, all-in-one profile | 2,000 events/s, up to 250 endpoints | Load bench |
| Ingestion throughput, distributed profile | 50,000 events/s, up to 10,000 endpoints | Load bench |
| Average volume per endpoint after filtering | < 1 GB/day (server), < 300 MB/day (workstation) | Ingestion statistics |
| Searchable retention | 12 months minimum | ClickHouse TTL and tiered storage policies |
| Agent offline autonomy | Full protection + 72 h of local buffer | Disconnection test |
| Backend availability (distributed profile) | 99.9 % | Monitoring |
| Event loss | 0 outside buffer saturation, alert on saturation | Sequence counters |
| Installing a single module | One command, under 10 min | Installation test in continuous integration |
| Footprint of a single lightweight module (WAF, DNS, identity provider), excluding storage | 1 vCPU and 1 GB of RAM maximum | Test bench |
| Metrics ingestion, all-in-one profile | 10,000 samples/s, up to 250 endpoints | Load bench |
| Metrics ingestion, distributed profile | 250,000 samples/s, up to 10,000 endpoints | Load bench |
| Metric query delay on rollups (30 days, one series) | < 2 s at the 95th percentile | Load bench |
| Metric retention per tier | Raw 15 days, 1 minute 90 days, 1 hour 13 months, 1 day 5 years | ClickHouse TTL and tiered storage policies |
| Metric threshold crossing → alert delay | < 60 s at the 95th percentile | End-to-end timestamps |
| Alert → first on-call notification delay | < 30 s at the 95th percentile | End-to-end timestamps |
| Full rebuild from Git | Identical, with no manual action apart from secrets | Weekly rebuild test |

**Sizing.** The documentation provides a storage calculator (endpoints × daily volume × retention × replication factor) and reference hardware profiles.

## 4. Deployment profiles and backend architecture

### Modular architecture

Each module is a standalone service: it installs alone (package, container or Helm chart), ships its own API, CLI, authentication and minimal storage, and can join a platform later without reinstallation.

| Module | Alone, it provides | Minimal storage | Combined, it gains |
| --- | --- | --- | --- |
| **EDR** (agents and management server) | Protection, telemetry and response on endpoints | Single-node ClickHouse, or export to a third-party SIEM | Multi-source correlation, AI, cases |
| **Detection and SIEM** | Ingestion, normalisation, Sigma rules, hunting (analyst-driven and automatic) | ClickHouse | Agents, connectors, AI |
| **Response and cases** | Cases, analysers, playbooks on alerts received through API or webhook | PostgreSQL | Every alert source |
| **AI** | Investigation and verdict on alerts received through API | None (stateless) | Tuning of the other modules' configurations |
| **Identity provider** | OIDC and SAML SSO, MFA | PostgreSQL | Access adapted to risk and device posture |
| **GRC** | Frameworks, manual evidence, reports | PostgreSQL | Automatically evaluated controls |
| **WAF** | Reverse proxy with automatic TLS, routing, load balancing and WAF | Local files, syslog export | Correlation, tuning by AI |
| **DNS** | Filtering resolver fed by threat intel | Local files | Sinkhole by playbook, correlation |
| **DHCP** | Kea server in high availability, lease history | PostgreSQL | Automatic quarantine, discovery |
| **NDR** | Zeek, Suricata, packet capture, file analysis | Local disk | Correlation with endpoints |
| **RMM** | Scripts, patch management, software deployment, remote shell and desktop | PostgreSQL | Remediation by playbook, security context on every device |
| **Monitoring** | Metrics, alerting, forecasting, synthetic checks, tracing, application health | ClickHouse | Correlation with security events, CMDB services |
| **On-call** | Alert routing, schedules, escalation, notifications, silences | PostgreSQL | Every IT and security alert source |
| **Status page** | Public status page, SLA and SLO reports per business service | PostgreSQL | Monitoring, on-call and CMDB |
| **Site collector** | Syslog, SNMP traps, flows and Redfish events from a remote site | Local disk buffer | Network devices, discovery, hardware health |
| **Vulnerability and compliance** | Inventory against CVE, end-of-life, configuration baselines, certificates | PostgreSQL | Risk score, GRC evidence |
| **MDM** | Apple and Android mobile device management | PostgreSQL | CMDB, access adapted to device posture |
| **CMDB** | Inventory of assets and their relationships, business services, licences | PostgreSQL | Criticality for the risk score, attack paths and circuit breakers |
| **Each connector** | Collection from, or action on, a third-party system | None | Feeds every other module |

**Shared lightweight core.** Every module ships the same core: REST API, CLI, local or OIDC authentication, audit log, declarative configuration engine. No central service is mandatory. When several modules coexist, a platform file declares their list; they then share authentication, the event bus and storage.

**Standard outputs.** Every module exports its events in ECS format (syslog, OTLP, NATS JetStream or webhook) to integrate with an existing SIEM such as Splunk, Sentinel, Elastic or Wazuh. One can therefore adopt a single module without replacing anything.

### Deployment profiles

Three profiles share the same code; only the number of modules, the ingestion mode and the redundancy change.

| Profile | Target | Components | Ingestion |
| --- | --- | --- | --- |
| **All-in-one** | Evaluation, SMEs up to 250 endpoints | One server (or VM), single-node ClickHouse, containerised backend services | Direct, with a disk buffer on the agent side and on the server side |
| **Distributed** | Mid-sized companies, SOCs, MSSPs | Multi-node ClickHouse cluster, redundant backend services, NATS JetStream | Through NATS JetStream |
| **Single module** | Targeted need: only the EDR, the WAF, the DNS, the identity provider… | One container or package, with the module's minimal storage | Direct, with optional export to a third-party SIEM |

**Component rules.** Durable state lives only in PostgreSQL, ClickHouse, NATS JetStream, MinIO (S3, headless, web console disabled) or Git. Every third-party component is headless: its own console or admin page is disabled or never exposed. Prometheus, VictoriaMetrics, Grafana, Grafana OnCall, Jaeger, Tempo, Parca, nmap and WSUS are not used, and Guacamole is not used for managed devices. Secrets are files encrypted with SOPS in Git by default; OpenBao is optional.

**No listening port on managed devices.** Every flow from a managed device is initiated by the device. Agentless equipment (switches, printers, BMCs, appliances) pushes to a site collector (section 22); polling it is an explicit per-device opt-in.

Migration from the all-in-one profile to the distributed profile is tooled and does not require reinstalling the agents.

&#91;embedded content: architecture · sources, ingestion, detection, decision\]

Events flow down from the sources to detection; every AI proposal goes through the validator and the history before travelling back up, signed, to the agents.

- **Decoupled ingestion.** In the distributed profile, a **NATS JetStream** buffer (Apache 2.0 licence) separates the agents from ClickHouse, absorbs peaks and prevents losses.
- **Normalisation.** All events are converted into a single schema: **ECS** is chosen because it is the closest to existing Sigma backends and to the ClickHouse table schemas. An OCSF export is available as output for customers who require it. Tetragon events are mapped to the Sigma Linux categories (`process_creation`, `file_event`, `network_connection`) so that the same rules apply to both systems.
- **Stream detection.** A stream correlation engine, plugged into NATS JetStream (or into the internal buffer in the all-in-one profile), handles time sequences, UEBA and Sigma correlation rules. It also runs single-event Sigma rules, compiled to ClickHouse SQL by an in-house converter.
- **Storage and search.** ClickHouse. Hunting is done in SQL (a KQL dialect is optional and experimental).
- **Retention.** ClickHouse TTL rules and storage policies manage hot, warm and cold storage. Cold data on S3 (or S3-compatible: MinIO, Ceph) allows hunting over 12 months without keeping everything on fast disk.
- **High availability (distributed profile).** ClickHouse cluster of at least 3 nodes, stateless backend services behind a load balancer, replicated configuration database, backup and restore tested automatically every week.
- **AI.** Support for external APIs and local models (Ollama, vLLM). A dedicated queue smooths the load and enforces a budget (number of calls and cost per day).
- **Communication with agents.** gRPC over mTLS, automatic certificate rotation, support for corporate HTTP(S) proxies, and fallback to TLS WebSocket when gRPC is filtered.

### Roaming devices

A device used remotely or on the move, without VPN, stays protected and managed as on the internal network.

- **Internet relay**: one or more lightweight relays, placed in a DMZ or with a hosting provider, expose only the agent channel (gRPC over mTLS, port 443). They store nothing and give access to no other platform function.
- **Automatic path selection**: the agent uses the internal server when it is reachable, otherwise the relay, without user intervention.
- **Relay security**: mandatory client certificate, up-to-date revocation list, per-agent rate limiting, no exposed administration interface. A revoked agent (a stolen laptop, for example) is refused immediately.
- **Bandwidth saving**: on a limited or metered connection, the agent sends alerts and critical events first, then the rest when the connection allows.
- **Remote actions**: isolation, forensic collection, restore and updates also work through the relay, with an adapted throughput.

## 5. Endpoint agents

### Supported systems

| System | v1 versions | Note |
| --- | --- | --- |
| Windows workstation | Windows 10 22H2, Windows 11 | Defender required in active mode for full blocking |
| Windows Server | 2016, 2019, 2022, 2025 | 2012 R2 not supported (end of support) |
| Linux | Kernel 5.4 or later: RHEL/Rocky/Alma 8 and 9, Debian 11 and 12, Ubuntu 20.04 to 24.04, SUSE 15 | Full Tetragon mode (eBPF) |
| macOS | Current and previous two major versions | Agent without a custom Endpoint Security client in v1 (section 21) |
| Android, iOS and iPadOS | Current and previous two major versions | Managed through MDM only, no agent (section 21) |
| Older Linux | Kernel 4.18 to 5.3 | Reduced mode: Tetragon with only the eBPF probes available on that kernel, reactive blocking only |

The exact compatibility list is published and tested in continuous integration on every release.

### Non-persistent virtual desktops

VDI environments (Citrix, Azure Virtual Desktop, VMware Horizon) and machines cloned from a master image are supported by a dedicated mode.

- **Master image mode**: the agent is installed in the image without an identity. Each clone generates its identifier at first boot, which avoids duplicate agents.
- **FIM baseline and inventory inherited** from the master image, instead of being recomputed at each boot. Only deviations from the image are monitored.
- **Short life cycle**: ephemeral machines are grouped by pool in the inventory, and removed automatically after they are destroyed, without polluting the fleet or raising silent-agent alerts.
- **Reduced footprint**: on-demand scans disabled on clones, shared signature cache, delayed agent start so as not to slow down logon.
- **History kept**: the events of each session remain searchable after the machine is destroyed, linked to the user and the pool.

### Windows agent

| Function | Component |
| --- | --- |
| Telemetry | **Sysmon**: processes, network, files, registry, image loads, DNS, WMI, process access (LSASS) |
| Antivirus | **Microsoft Defender Antivirus**: on-access and on-demand scanning, AMSI for PowerShell, VBA and JScript |
| Behavioural blocking | **ASR** rules, **Controlled Folder Access**, **Network Protection**, PUA blocking, reactive kill by the agent |
| Hash blocking | **App Control for Business** (WDAC), supplemental deny policies (see section 7) |
| Blocking dropped executables | Sysmon, events 27 (FileBlockExecutable) and 28 (FileBlockShredding) |
| Network blocking | **Windows Firewall** |
| Logs | Security, PowerShell Script Block Logging, Defender Operational |
| YARA | **YARA-X** driven by the agent, for targeted file and memory scans |

**Sysmon distribution.** The Sysinternals licence forbids its redistribution: the agent downloads Sysmon from Microsoft and checks its signature before installation. An internal mirror is possible for isolated networks, fed by the administrator.

### Linux agent

| Function | Component |
| --- | --- |
| Telemetry | **Tetragon** (eBPF): processes, files, network, kernel modules, privilege escalations |
| Behavioural blocking | Tetragon: SIGKILL and system call override before the action executes; BPF-LSM when the kernel allows it |
| File scanning | **YARA-X**, with threat intel hashes |
| Network blocking | **nftables** |
| Logs | journald / syslog through **Vector** |
| Older kernel fallback | **Reduced eBPF**: Tetragon limited to the available probes, reactive kill by the agent |

**Containers.** Tetragon links each event to its container and enriches it with the runtime metadata (containerd, Docker, CRI-O): image, container name, pod, Kubernetes namespace. This makes it possible to detect container escapes, privileged containers and container **drift** (execution of a binary absent from the original image).

### Common to both agents

- **Sensor orchestration.** The agent deploys and updates the components, applies their configurations, constantly checks that they are running and have not been disabled, and forwards their events.
- **Capability detection.** At installation and then at every restart, the agent measures what the system allows (kernel version, `CONFIG_BPF_KPROBE_OVERRIDE`, BPF-LSM active, Defender active or passive, Tamper Protection) and chooses the best blocking mode. The effective mode is displayed for each endpoint.
- **Local filtering and aggregation.** Repetitive events are deduplicated and aggregated before sending, within the volume budget of section 3.
- **No listening port.** The agent never opens a listening socket for remote access: the agent channel, remote shell, file transfer and remote desktop are all initiated by the device, to the server or a relay.
- **Offline operation.** Cached policies and rules, encrypted local buffer of at least 72 h, deferred sending on reconnection, alert if the buffer saturates.
- **Embedded osquery.** Inventory, on-demand hunting and scheduled queries.
- **FIM.** osquery computes a hash baseline at onboarding. Real-time monitoring is provided by Sysmon on Windows (files and registry) and by Tetragon on Linux. Monitored locations:
  - **Windows:** persistence keys (Run, Services, IFEO, Winlogon), scheduled tasks, startup folders, system binaries;
  - **Linux:** `/etc/passwd`, `shadow`, `sudoers`, cron, systemd units, `authorized_keys`, `ld.so.preload`, system binaries.

  Changes are correlated with the package manager and Windows Update to remove the noise of legitimate updates.
- **Automatic honeytokens.** Deployed at installation according to a **deterministic role → honeytokens table**, versioned and auditable. The AI can propose additions for roles that are not covered, subject to the validator.
  - anti-ransomware canary files;
  - fake cloud credentials (`.aws/credentials`), fake SSH keys, fake password files;
  - fake in-memory credentials (honeyhash) on Windows.

  Any use of a honeytoken raises a critical alert. On Windows, reads are detected through object access auditing (SACL on the decoys, event 4663), because Sysmon does not log reads. Use of a honeyhash is detected on domain controllers (events 4625, 4768, 4771 on the decoy account), which requires collecting their logs. On Linux, Tetragon monitors the opening of decoys.
- **Tamper resistance.** Stopping, uninstalling or modifying the agent or its sensors requires an authorisation token signed by the platform. A determined local administrator can always bypass these protections (root on Linux; on Windows, PPL protection would require an ELAM driver certified by Microsoft, out of v1). The goal is therefore to **make tampering hard and always visible**: a silent, stopped or modified agent or sensor raises an alert in under 5 minutes thanks to the heartbeat monitored on the server side.
- **Response actions.** Network isolation (keeping the connection to the platform), process kill, file quarantine, remote shell, forensic collection. Every command received is signed by the platform and checked by the agent before execution (section 12).
- **Agent update.** Signed packages, verification before installation, automatic rollback to the previous version if the agent does not restart healthily.

### Additional protection and visibility

**Ransomware recovery.**

- **Windows.** The agent creates and manages its own VSS snapshots (by default every 4 hours, 10 % of the disk) and protects existing ones. Any attempt to delete or shrink snapshots (`vssadmin`, `wmic shadowcopy`, `Win32_ShadowCopy`, resizing the storage) triggers a reactive kill and a critical alert.
- **Linux.** Same principle when the file system allows it (Btrfs, ZFS, LVM thin); otherwise the feature is reported as unavailable on the endpoint.
- **Restore.** After a malicious verdict, the platform lists the files created, modified or encrypted by the offending process tree (Sysmon or Tetragon events) and offers to restore them from the last snapshot prior to the infection, in one click, with human approval. Every restored file is logged.
- **Limit.** Snapshots stay on the same disk: they do not replace an offline backup.

**Device control.**

- **Windows:** native removable storage access policies (read-only, block, exceptions by vendor ID, product ID or serial number), logging through PNP auditing (event 6416).
- **Linux:** **USBGuard**, with default blocking of new HID keyboards appearing after boot (BadUSB-type attacks).
- Audit, read-only or block modes, per endpoint group; starts in audit for 14 days like the ASR rules.

**Security configuration assessment (SCA).**

- The agent assesses each endpoint against hardening policies in YAML, run through osquery and read-only local checks.
- Policies provided for Windows, Windows Server and the supported Linux distributions, mapped to the CIS recommendations, the ANSSI guide and the frameworks of the GRC section.
- Result per endpoint: score, failed controls, justification and recommended fix. The results feed the GRC section and the risk score directly.
- No automatic remediation: a fix can be triggered by playbook, with human approval.

**Network discovery by agents.**

- **Passive (default):** each agent listens to ARP, DHCP, mDNS, LLMNR, NetBIOS and SSDP on its segment to spot neighbouring devices.
- **Active (option):** designated agents probe only unknown addresses, with little traffic. Sensitive ranges (OT, medical devices) are excluded by default.
- Discovered devices are merged with DHCP logs and the NDR in the inventory. Every new unmanaged device raises an alert and a proposal to install the agent.

**Hardened protection during an attack.**

- When a live, human-operated attack is detected on an endpoint (administration tools used abnormally, reconnaissance, disabling of protections), the agent switches for 24 hours to a **hardened mode**: actions that are usually tolerated but favoured by attackers are blocked without waiting for a verdict.
- Examples: running unapproved remote access or transfer tools, `PsExec` and equivalents, creating services and scheduled tasks, changing firewall rules, deleting logs or snapshots, all ASR rules in block mode.
- The mode can also be enabled manually by an analyst, or by playbook on every machine of the same incident, when full isolation would disrupt the business too much.
- **Safe mode blocking**: any attempt to force a reboot into safe mode (`bcdedit /set safeboot`) is permanently blocked, because attackers use it to boot without protection.
- Activation, duration and blocked actions are visible on the endpoint and in the incident; lifting the mode is logged.

**Network honeypots.**

- Fake machines based on **OpenCanary**, deployable as a container on any Linux agent or as a virtual appliance, with a recommendation of at least one per subnet.
- Imitated services to choose from: SMB, RDP, SSH, HTTP, MSSQL, MySQL, FTP, Telnet, SNMP. Every connection raises a critical alert, because no legitimate use exists.
- **Breadcrumbs**: the honeytokens placed on endpoints (fake credentials, fake saved RDP connections, fake network drives) point to the honeypots, to lure an attacker exploring a compromised machine.
- Honeypots appear in internal DNS under attractive names (for example `backup-srv02`, `sql-finance`) and are excluded from vulnerability scans and active network discovery.

**Adaptive per-user hardening.**

- For 30 days, the agent learns which sensitive tools each user–device pair actually uses: interpreters (PowerShell, `wscript`, `mshta`), misused system tools (`certutil`, `bitsadmin`, `regsvr32`, `rundll32`), remote administration tools.
- It then proposes targeted restrictions: block a tool that is never used, or allow only certain actions of a used tool (PowerShell without downloads or encoded execution, for example). Enforced through App Control and ASR on Windows, TracingPolicies on Linux.
- Proposals go through the validator and the AI operating mode (section 8), with a prior audit mode. A change in the user's role restarts the learning.

**Patch management.**

- Deployment of operating system and third-party application updates: Windows Update, winget on Windows, package manager on Linux.
- Declarative policies: maintenance windows, rings (pilot, then general), deadlines by severity, automatic priority for KEV vulnerabilities and for those on an attack path.
- Scheduled reboots that the user can defer within a set limit; patch compliance state reported to GRC.

**Disk encryption.**

- Management of native encryption: BitLocker on Windows, LUKS on Linux (checking and inventory; encrypting an existing disk on Linux is not automated).
- Recovery keys escrowed in the secrets vault (section 12), with logged access and dual approval.
- Encryption state per endpoint, usable as an access condition by the identity provider and reported to GRC.

**Browser extensions.**

- Inventory through osquery of Chrome, Edge and Firefox extensions, with their permissions.
- Detection of known malicious extensions (threat intel), extensions with excessive permissions or unapproved extensions; allowlist of extensions enforced through browser policy.

## 6. Connectors

Connectors are used to **ingest** detection sources and to **act** on third-party systems. Their credentials are stored in a secrets vault (section 12), with the minimum rights needed for each action.

### Detection sources

| Source | What it provides |
| --- | --- |
| **Identity (ITDR)** | Active Directory and Entra ID: Kerberoasting, DCSync, password spraying, impossible logins, creation of privileged accounts. Decoy accounts and SPNs deployed on approval. |
| **SaaS** | Microsoft 365 and Google Workspace: mail forwarding rules, malicious OAuth consents, mass sharing. |
| **Cloud** | AWS CloudTrail, Azure Activity, GCP Audit: access key creation, IAM changes, log disabling. |
| **Kubernetes** | Audit logs: exec into a pod, role creation, access to secrets, suspicious deployments. |
| **Existing DNS and DHCP logs** | Windows DNS/DHCP, Kea, ISC, Infoblox, routers: IP ↔ MAC ↔ hostname history, device discovery, suspicious queries. Works without the optional module of section 14. |
| **Perimeter** | Firewall, proxy and VPN logs. |
| **Email** | Mail gateway: phishing, attachments, header analysis. |
| **Network (NDR)** | Zeek and Suricata: agentless devices (printers, IoT, OT) and lateral movement. |

Decoy accounts and SPNs in Active Directory are never created without explicit approval from a domain administrator: they modify a production directory.

### Actions

| Action | Targets | Default approval |
| --- | --- | --- |
| IP or domain blocking | Firewalls, proxies, DNS | Automatic on a malicious verdict, limited duration |
| Session revocation | Entra ID, Google Workspace | Automatic on a malicious verdict |
| Account disabling | AD, Entra ID | Human approval; never automatic for a privileged account |
| Ticketing and messaging | Jira, GLPI, Slack, Teams, email | Automatic |
| On-call | PagerDuty, Opsgenie | Automatic |

**Declarative, standalone connectors.** A connector is a versioned, signed package: a declarative manifest (requested rights, exposed actions, configuration schema) and its code. For a REST API, the connector skeleton can be generated from its OpenAPI specification, then reviewed, completed and tested. Each connector runs alone, to collect towards any standard output or to expose its actions through an API, or within the platform. Its configuration is a file, never a form.

### Backup monitoring

Attackers destroy backups before encrypting. Dedicated connectors monitor backup solutions (Veeam, Proxmox Backup Server, Bacula, Borg and Restic, AWS, Azure and GCP snapshots).

- **Detection**: deletion of backups or restore points, reduced retention, immutability disabled, jobs stopped or repeatedly failing, unusual login to the backup console, creation of a backup administrator account.
- **Correlation**: these events sharply raise the risk score and, combined with other signals (VSS snapshot deletion, reconnaissance), trigger the hardened protection mode on the affected machines.
- **Coverage**: list of critical servers without a recent backup, or whose last tested restore is too old.
- **Evidence for GRC**: date of the last successful backups, immutability enabled, restore test results.

## 7. Detection and correlation

### Where each detection runs

Preventive blocking only exists for local mechanisms. A central detection triggers at best a reactive response, a few seconds to a few minutes after the facts.

| Mechanism | Location | Effect | Works offline |
| --- | --- | --- | --- |
| ASR rules, Controlled Folder Access, Network Protection | Windows endpoint | Preventive blocking | Yes |
| App Control (denied hashes) | Windows endpoint | Preventive blocking | Yes |
| Sysmon 27/28 | Windows endpoint | Preventive blocking | Yes |
| Tetragon TracingPolicies (SIGKILL, override, BPF-LSM) | Linux endpoint | Preventive blocking | Yes |
| Defender, YARA-X | Endpoint | Blocking or quarantine | Yes |
| Windows Firewall, nftables (IP IOCs) | Endpoint | Network blocking | Yes, cached list |
| Lightweight agent rules (honeytokens, reactive kill) | Endpoint | Reactive kill | Yes |
| Single-event Sigma (compiled to ClickHouse SQL) | Central | Alert, then playbook | No |
| Correlation, sequences, UEBA (stream engine) | Central | Alert, then playbook | No |
| Connectors (identity, cloud, SaaS, NDR) | Central | Alert, then playbook | No |

### Rules and engines

- **Rules.** Sigma for central detection (including Sigma correlation rules), ASR and App Control rules on Windows, Tetragon TracingPolicies on Linux, YARA for files and memory.
- **Multi-source correlation and sequences.** Example: a phishing email, then a child process of Outlook, then a connection to a malicious IP, within a 30-minute window for the same user.
- **Entity graph.** Links between users, hosts, IPs, domains, files and containers, for investigation and correlation.
- **UEBA.** Behavioural baseline per user and per machine: unusual hours, abnormal volumes, first login to a machine. Learning period of at least 30 days, without alerts, before activation.
- **Threat intel.** Native, stored in ClickHouse: bulk feed connectors (STIX/TAXII 2.1, abuse.ch, CSV and JSON lists, CrowdSec blocklist, MISP-format feeds read as files), an IOC table with TTL expiry and scoring, ClickHouse dictionaries for ingest-time enrichment (`ip_trie` for IPs and CIDRs), scheduled SQL for retro-matching, and STIX/TAXII export for sharing. MISP and OpenCTI are optional connectors only. Free Defender does not handle custom IOCs; they are therefore enforced through App Control (hashes), the firewall and nftables (IPs), and the filtering DNS if the optional module is active.
- **IOCs in App Control.** To avoid bloating the policies, hashes are grouped in a single supplemental deny policy, regenerated at most once per hour, with a size cap. Only recent, high-score IOCs go into it; the others stay in detection.
- **MITRE ATT&CK coverage.** Map of detected, blocked and uncovered techniques, per system and per source.
- **Blind spot detection.** A silent agent or sensor, a log source that stops reporting or an abnormal drop in volume raises an alert.
- **Vulnerabilities.** The osquery inventory is correlated with CVEs, the EPSS score and the CISA KEV catalogue to prioritise by real exposure.

### Risk and exposure

**Risk score per entity.**

- Each detection adds risk points to the entities involved (user, host, IP, container, cloud account), including detections too weak to raise an alert on their own.
- Points are weighted by severity, by how rare the detection is for this entity and across the whole fleet, and by its historical reliability (measured false positive rate). They decay over 7 days.
- The score is normalised from 0 to 100 and displayed wherever the entity appears. Above a threshold, an incident is created even if no individual alert was critical.
- The score is used to prioritise the alert queue and the AI investigation. Manual adjustments are logged and justified.

**Attack paths.**

- The platform builds an exposure graph from its own data: Active Directory group memberships and ACLs, open sessions, local administration rights (osquery), KEV vulnerabilities, SCA results, Internet-exposed services (perimeter connectors) and cloud IAM rights. Attack paths are computed from this entity graph.
- **Critical assets** tagged automatically (domain controllers, AD CS, backup servers, hypervisors, secrets vaults) or manually.
- Computation of paths from likely entry points (user workstations, exposed or vulnerable machines) to critical assets, and highlighting of **choke points** where several paths cross.
- Recommendations ranked by number of paths closed. Paths feed the risk score, vulnerability prioritisation and the GRC section.

**Leaked credentials.**

- Monitoring of the organisation's email domains in breach databases and threat intel feeds (for example the Have I Been Pwned domain monitoring API, or infostealer log feeds), with the API key provided by the user.
- **Offline password check**: the password hashes of Active Directory and of the built-in identity provider are compared locally with lists of compromised passwords, without ever sending a password or a full hash outside.
- A match on an active account raises its risk score and triggers a playbook: forced reset, revocation of sessions and tokens, MFA check.

**Active Directory and Entra ID posture.**

- Scheduled assessment of directory configuration, with checks written by the project:
  - **Active Directory:** too many or inactive privileged accounts, accounts with SPNs exposed to Kerberoasting, accounts without Kerberos pre-authentication, unconstrained delegation, vulnerable AD CS templates, age of the `krbtgt` password, no LAPS, GPOs editable by non-administrators;
  - **Entra ID:** legacy authentication still enabled, too many global administrators or global administrators without phishing-resistant MFA, risky application consents, overly broad guest access, no break-glass accounts.
- Result: posture score, failed controls ranked by severity, justification and recommended fix. The results feed attack paths, the risk score and the GRC section.

**Active Directory and Entra ID audit.**

Posture says how the directory is configured; audit says who changed it, when and how.

- **Audit policy deployed as code**: the agent installed on domain controllers applies the advanced audit policy and the required SACLs (directory service changes, account and group management, Kerberos, logons), then checks that they stay active.
- **Collection** of domain controller events: account creation, change, enabling, disabling and deletion (4720, 4722, 4725, 4726, 4738), password resets (4724), group additions and removals (4728, 4732, 4756 and their counterparts), object changes (5136, 5137, 5141), replication operations (4662), Kerberos (4768, 4769, 4771), lockouts (4740). For Entra ID, audit and sign-in logs through the Microsoft Graph API.
- **Before and after values**: every change is recorded with the old and new value of the attribute, including when the Windows event does not contain them, thanks to regular directory snapshots and replication metadata.
- **GPO tracking**: change, creation, linking and deletion, with the content diff (settings and SYSVOL files) between two versions.
- **Alerts on sensitive changes**: addition to a privileged group, AdminSDHolder change, GPO linked to the domain controllers OU, new trust relationship, SID History addition, delegation change, registration of a rogue domain controller (DCShadow), change made outside usual hours or by an unusual account.
- **Lockout source search**: for a locked account, identification of the machine and the process sending the wrong passwords.
- **Reports**: complete history of an account, a group or a GPO, changes per administrator, password resets, inactive accounts, members of privileged groups at a given date.
- **Attribute rollback**: a change can be undone by restoring the previous value (group membership, account attribute), with dual approval and logging. Deleted objects go through the Active Directory recycle bin when it is enabled.
- The results feed detection, the risk score, attack paths and GRC (traceability of privileged access).

**External attack surface (EASM).**

- From declared seeds (domains, IP ranges, cloud accounts), continuous discovery of Internet-exposed assets: subdomains (Certificate Transparency logs, DNS), open services, certificates, detected technologies.
- Orchestrated open source tools (for example subfinder, naabu, httpx, nuclei) with a pace and targets limited to assets whose ownership is proven.
- Detection of unknown assets (shadow IT), exposed sensitive services (RDP, databases, administration interfaces), expired certificates and exposed KEV vulnerabilities. The results become entry points of the attack paths.

**Cloud and Kubernetes posture.**

- **Cloud**: scheduled assessment of AWS, Azure and GCP account configuration with **Prowler**: public storage, overly broad IAM roles, old access keys, disabled logging, missing encryption, security groups open to the Internet.
- **Kubernetes**: checking of clusters with **Trivy** (CIS recommendations) and of deployed manifests: privileged containers, no resource limits, overly powerful service accounts, plaintext secrets, no network policies.
- **Container images**: analysis of vulnerabilities and embedded secrets with **Trivy**, in registries and on running images, cross-checked with Tetragon to prioritise images that are actually running and exposed.
- **Infrastructure code**: the same checks apply to Terraform, OpenTofu, Helm and Kubernetes files before deployment, in the customer's continuous integration.
- The results feed attack paths, the risk score and GRC.

### Applied intelligence

- **Retroactive IOC matching.** Every new IOC (hash, IP, domain, URL) is automatically searched for across the whole retained history, up to 12 months. A domain declared malicious today thus reveals every device that contacted it before.
- **Emerging threat sheets.** For each tracked campaign (ransomware, exploited vulnerability, actor), a sheet shows: IOC matches in the history, detection rules present or missing, vulnerable or misconfigured assets involved, and recommended actions. Coverage is checked by the detection tests.
- **Grouping by campaign or actor.** Alerts linked to the same campaign, malware or actor (according to the threat intel associations) are merged into a single incident, more reliable than the alerts taken in isolation.

### Enrichment: at ingestion or at alert time

When enrichment happens is chosen per source and per field type, in the declarative configuration (section 11).

|  | At ingestion (every log) | At alert time |
| --- | --- | --- |
| **Usable sources** | Only threat intel **stored in the platform**: STIX/TAXII, abuse.ch, CrowdSec blocklist and other feeds synchronised in bulk into ClickHouse, internal lists, CMDB, geolocation and ASN in a local database | Local database, plus external analysers queried on demand (VirusTotal, AbuseIPDB, Shodan…) |
| **Network calls** | None: matching is done in memory, in the pipeline | API calls one at a time, with cache, quotas and TLP and PAP rules |
| **What you gain** | Every event carries its matches (ECS `threat.*` fields): you can search, filter and hunt on threat intel across the whole history | Rich, up-to-date enrichment, at no cost on log volume |
| **Limit** | Enrichment reflects the IOC state at ingestion time; IOCs that arrive later are covered by retroactive matching | Logs that do not trigger an alert are not enriched |

- **Absolute rule**: no external API is called for a log. One-at-a-time queries to a third-party service are reserved for alerts, cases and manual analyses, which protects ingestion throughput, API quotas and data confidentiality at the same time.
- **By default**: enrichment at ingestion enabled for IPs, domains, URLs and hashes against the local database; external enrichment at alert time only.
- **Every enrichment is dated and sourced** (feed, version, confidence score at matching time), so that an analyst knows where a label comes from and whether it is still valid.

### Continuous testing

Atomic Red Team automatically checks that detections work, in particular after every tuning. Tests run on **dedicated test endpoints**, representative of each role, and never on production machines. Only tests marked harmless may be allowed in production, by explicit decision. A tuning that makes a test fail is rolled back automatically.

## 8. Role of AI and guardrails

The AI investigates, explains and proposes; it only acts through bounded tools, and every change goes through a deterministic validator. It has no direct access to endpoints or connectors.

### At agent onboarding

- The AI analyses the endpoint through osquery: services, installed software, probable role (domain controller, SQL server, developer workstation, Kubernetes host…), presence of a third-party antivirus, backup and indexing tools.
- It starts from **deterministic reference configurations** per role (for example sysmon-modular for Sysmon) and proposes adjustments:
  - **Windows:** Sysmon configuration, Defender exclusions, ASR rule mode (audit or block);
  - **Linux:** Tetragon TracingPolicies, YARA-X scan scope (for example `/tmp`, `/home`, `/var/www`, downloads), exclusions;
  - **Both:** FIM exclusions.
- ASR rules start in **audit mode for 14 days**, then switch to block mode rule by rule if no recurring false positive is observed.

### For each alert

- **Deterministic pre-processing.** Deduplication and grouping of alerts before any AI call, to limit cost and noise.
- **Investigation.** Process tree, reputation of hashes, IPs and domains, entity graph, endpoint history, similar alerts.
- **Reasoned verdict**: malicious, suspicious, benign or false positive, with a confidence level and the evidence behind it.
- **Malicious verdict.** Playbooks triggered within the limits of the circuit breakers (section 10), related alerts grouped into an incident.
- **Benign or false positive verdict.** The alert is closed, but **no exclusion is created on a single verdict** (see exclusion rules below).

### Rules for creating an exclusion

An exclusion is only proposed if all of the following conditions are met:

1. the same behaviour is judged benign at least **5 times over at least 3 distinct days**;
2. it appears on **several endpoints**, or on an endpoint whose role explains it (a backup tool on a backup server, for example);
3. the original alert is **neither critical nor linked to a honeytoken**;
4. the binary involved is **signed by a trusted publisher**, or its hash is known and stable.

The exclusion is then built with the **narrowest possible scope**: hash rather than path, path rather than name, one endpoint rather than a group, a precise command line rather than a whole process. It is applied in the right place (Sigma rule, Sysmon, Defender, Tetragon or YARA-X) and carries a **lifetime of 90 days**, renewable after review.

### Policy validator (non-AI)

Every tuning goes through a deterministic, versioned and tested validator, which refuses in particular:

- any global exclusion of a system binary or an interpreter (`powershell.exe`, `cmd.exe`, `rundll32.exe`, `bash`, `python`…);
- any path-based exclusion of an unsigned binary;
- any exclusion targeting a honeytoken, the agent or its sensors;
- any exclusion of a user-writable directory (`%TEMP%`, `Downloads`, `/tmp`);
- disabling a critical ASR rule (LSASS credential theft, execution from attachments, Office child processes);
- any change that would reduce the MITRE coverage of a technique to zero.

### Operating mode

Three modes can be configured, per change type and per endpoint group: **suggestion only**, **human approval** (default) or **autonomous**. Switching to autonomous requires having approved at least 50 suggestions with a 95 % acceptance rate on the scope concerned.

### Resistance to manipulation

An attacker may try to influence the AI, for example by slipping text into a command line, a file name or a log field, or by repeating a behaviour to make it pass as benign.

- Telemetry data is passed as tagged data and never as instructions.
- The AI only calls read-only tools during the investigation; all writes go through the validator.
- The exclusion rules above prevent a behaviour repeated on a single compromised machine from becoming an exclusion.
- A random sample of **5 % of "benign" and "false positive" verdicts** is submitted to human review every week.
- Every exclusion created is reviewed automatically if a critical alert later occurs on the same scope.

### Quality and cost

- **Evaluation set.** A corpus of labelled alerts (malicious and benign) ships with the platform. Any model, external or local, must reach a minimum threshold (for example 90 % recall on malicious alerts) before activation, and the test is replayed at every model change.
- **Tracking.** Agreement rate with analysts, rate of verdicts later contradicted, investigation time.
- **Budget.** Cap on calls and cost per day, with an alert at 80 % and a switch to degraded mode beyond it, with no impact on blocking.

### Analyst and integration assistance

These three functions always produce a visible and verifiable result (query, parser, rule) before any execution or installation.

**Natural language hunting.**

- The analyst asks a question in French or English; the AI translates it into a ClickHouse SQL or osquery SQL query, displayed and editable before execution.
- Read-only queries, with bounded time range and cost, with an explanation of the logic.
- A fruitful hunt can be saved or converted into a Sigma rule, which then goes through the validator and the detection tests.

**Assisted import of log sources.**

- The user provides a log sample from an unsupported source; the AI proposes a parser (Vector) and the mapping to ECS.
- The parser is validated deterministically on the sample (parse rate, mandatory fields), reviewed by a human, then versioned like any configuration.

**Rule migration from other SIEMs.**

- Import of Splunk (SPL), Microsoft Sentinel (KQL), Elastic (EQL, ES|QL), QRadar (AQL) and Wazuh rules.
- Each rule is first matched against existing Sigma rules (SigmaHQ); failing that, it is translated into Sigma, with automatic correction on syntax errors (three attempts at most).
- Status per rule: translated, partial (blockers explained: missing field or source) or not translatable. Installation only after human approval and passing the detection tests.

### Automatic threat hunting

Proactive hunting that runs on its own, on top of the analyst-driven natural language hunting above.

- **Hunt packs as code.** Versioned files (query in ClickHouse SQL or osquery SQL, ATT&CK technique, hypothesis, schedule, time window, cost bound, expected baseline), kept in the Git repository like rules, with tests on the lab corpus.
- **Scheduled runs.** Each pack runs on its schedule across the history in ClickHouse and live on endpoints through osquery, read-only, with bounded time range and cost.
- **Intel-triggered runs.** A new IOC, a CVE marked KEV or a new threat report triggers retro-hunts over the history, reusing the threat intelligence retro-matching.
- **Statistical hunts.** Baselines per entity and stack counting (rare process, rare parent-child pair, rare destination, first-seen binary, new persistence entry, beaconing regularity) surface the rare and the new, not only known indicators.
- **AI hypotheses.** The AI module proposes new hypotheses from recent alerts, intelligence and coverage gaps (ATT&CK techniques without detection), always as a displayed, editable query bound by the same read-only and cost limits; never an action.
- **Findings.** Grouped per entity, scored into the risk score, and opened as a low-priority case or attached to an existing one; a fruitful hunt is proposed as a Sigma rule that goes through the policy validator and the detection tests.
- **Coverage report.** Which techniques were hunted, when and with which result, feeding the GRC evidence.

## 9. Incident response and forensics

- **Incident management.** Alert grouping, timeline, comments, assignment, status, severity, response SLA per severity.
- **Remote forensic collection.** Memory dump and artefacts: MFT, prefetch, Amcache, logs, shell histories. Performed by the Ostyr agent and osquery. Every collection is hashed and timestamped to preserve the chain of custody.
- **Manual and automated actions.** Isolation, kill, quarantine, account disabling, network blocking, all reversible from the incident.
- **Remote shell.** Reserved for a dedicated role, subject to MFA at every opening, fully recorded (commands and outputs), and subject to dual approval on critical assets.
- **Incident report.** Generated by the AI then reviewed by an analyst: summary, timeline, impact, actions taken, recommendations. PDF and Markdown export.
- **Notification obligations.** The incident can be marked as falling under the GDPR (personal data breach, notification within 72 h) or NIS 2 (early warning within 24 h); the platform then displays the deadlines.

### Advanced case management

- **Case templates** per incident type (ransomware, phishing, account compromise, CEO fraud, data leak), with a predefined task list, mandatory fields and duration indicators.
- Assignable **tasks**, with status, due date and a timestamped action log, including the commands run, for a reproducible investigation.
- **Observables** with TLP and PAP marking, IOC status, source, and automatic detection of observables **already seen** in other cases.
- **Merging and linking of cases** related to the same threat, suggested by overlapping observables.
- **Evidence register** linked to the chain of custody of the forensic collection.
- **Threat intel exchange**: creating a case from a STIX bundle, exporting a case as STIX/TAXII. An optional MISP connector adds exchange with MISP servers.
- **Sharing between tenants** (MSSP): a case, a task or an observable can be shared with another tenant according to explicit rules.

### Observable analysers

- One-click analysis, or automatic analysis during the AI investigation, of hashes, IPs, domains, URLs, email addresses and files.
- **Local analysers:** internal threat intel, platform history, YARA-X, entity graph.
- **External analysers** (API key provided by the user): VirusTotal, AbuseIPDB, URLhaus, Shodan, among others. A small set of in-house analysers ships with the platform.
- Optional connector to an external **sandbox** (for example CAPE) for detonating suspicious files.
- **Sharing rules:** TLP and PAP marking decides what may leave. A TLP:RED observable or a file never leaves the platform without explicit authorisation. Results are cached.

### Automatic containment of compromised accounts

- When an incident is judged malicious with high confidence and an account is identified as compromised, the platform contains that account **on every endpoint at once**:
  - closing the account's open sessions;
  - temporarily refusing its new interactive and network logons (deny logon rights on Windows, local lock and PAM rule on Linux);
  - revoking cloud and SaaS sessions through the identity connectors.
- The originating host is isolated in parallel if the circuit breakers allow it.
- Privileged and break-glass accounts follow the rules of section 10: human approval is mandatory.
- Every action can be undone in one click from the incident, and is lifted automatically after 24 hours without confirmation.

### Fleet-wide forensics

- **Forensic hunts**: the same artefact (prefetch, Amcache, scheduled tasks, shell history, recent files) is collected in one go across the whole fleet or a filtered group (system, tag, role), with results viewable as they arrive.
- **Declarative artefacts**: each collection is a versioned, configurable and tested file; written in an in-house artefact format, run by the Ostyr agent and osquery.
- **Offline collector**: generation of a standalone, signed executable, to collect on a machine without an agent or cut off from the network. Results are encrypted, then imported into the case with their hash.

### Built-in analysis tools

- Embedded **CyberChef**, to decode, decompress and analyse an artefact (encoded PowerShell, base64, XOR) without taking it out of the platform. The recipes used are recorded in the case log.

### Phishing reporting

- **Reporting mailbox**: users forward a suspicious email (or use their mail client's button) to a dedicated address, collected by the Microsoft 365, Google Workspace or IMAP connector.
- **Automatic triage**: headers (SPF, DKIM, DMARC), URLs and attachments passed to the analysers and the sandbox, search for identical emails received by other users, AI verdict.
- **Response**: if the email is malicious, playbook to remove it from every mailbox, block the sender and the URLs, and search for clicks. The user receives the verdict by email, which encourages reporting.

### Out-of-band crisis mode

When Active Directory, email or instant messaging are compromised, the team can no longer coordinate through the usual channels, which the attacker may be reading. Crisis mode provides an independent channel.

- **Activation** manually, or proposed automatically on a critical incident affecting the directory, email or backups.
- **Separate identities**: members of the crisis cell log in with break-glass accounts specific to the platform (WebAuthn mandatory), independent of the organisation's directory and identity provider.
- **Crisis room per incident**: encrypted messaging, timestamped decision log, list of actions with owner and due date, shared documents (response plan, contacts, evidence).
- **Out-of-band notifications**: SMS, calls through the on-call service, or an independent mobile messaging app (Signal, Matrix), never through the organisation's messaging.
- **Crisis directory**: contacts for management, the DPO, the cyber insurer, the authorities (ANSSI, CNIL, law enforcement) and incident response providers, kept up to date and accessible offline.
- **Ready-to-use response plans** (ransomware, directory compromise, data leak), versioned like the rest of the configuration, with the notification obligations described above.
- **Backup hosting**: the crisis room can be moved to a separate instance, outside the organisation's network, to stay accessible if that network is fully compromised or cut off.
- All crisis activity then feeds the incident report and the post-incident review.

## 10. Automation engine and circuit breakers

Playbooks are written in YAML, versioned (section 11) and testable in simulation mode. They support conditions (`if / else`), variables, connector calls, approval steps and compensation (automatic undo of an action).

There is no visual editor: a playbook is code, reviewed in a merge request, tested in continuous integration by simulation on sample alerts, then deployed like the rest of the configuration (section 11). A playbook can run in the response module alone, triggered by an alert received through API or webhook.

### Global circuit breakers

These limits apply to every playbook and can only be lifted by an administrator, with logging:

| Limit | Default value |
| --- | --- |
| Automatic isolations | 5 per hour, 20 per day across the whole fleet |
| Automatic account disablings | 3 per hour |
| Automatic IP or domain blocks | 50 per hour, maximum duration 7 days |
| Assets never isolated automatically | Domain controllers, hypervisors, servers tagged "critical" |
| Accounts never disabled automatically | Privileged accounts, break-glass accounts, tagged service accounts |
| Reserved ranges (IPs never blocked) | Internal networks, DNS resolvers, gateways, the platform itself |
| RMM script executions | 20 machines per execution; beyond that, dual approval |

Beyond a limit, the playbook stops, the action waits for approval and an on-call alert is raised.

### Example

```yaml
name: Block confirmed C2
version: 3
mode: enforce            # simulate | enforce
trigger:
  alert.verdict: malicious
  alert.category: command_and_control
  alert.confidence: ">= 0.8"
steps:
  - if: "{{ alert.remote_ip and alert.remote_ip.reputation >= 80 and not alert.remote_ip.is_internal }}"
    then:
      - connector: fortigate
        action: block_ip
        params: { ip: "{{ alert.remote_ip }}", duration: 24h }
        compensate: unblock_ip
  - if: "{{ alert.domain }}"
    then:
      - connector: dns          # only if the optional DNS module is active
        action: sinkhole
        params: { domain: "{{ alert.domain }}", duration: 24h }
  - if: "{{ alert.host.criticality != 'critical' }}"
    then:
      - action: isolate_endpoint
        params: { host: "{{ alert.host }}" }
    else:
      - action: request_approval
        params: { role: soc_lead, timeout: 15m, action: isolate_endpoint }
  - if: "{{ alert.user and not alert.user.is_privileged }}"
    then:
      - connector: entra_id
        action: revoke_sessions
        params: { user: "{{ alert.user }}" }
  - connector: slack
    action: notify
    params: { channel: "#soc", message: "C2 confirmed on {{ alert.host }}: actions {{ playbook.actions_done }}" }
on_error:
  - connector: pagerduty
    action: page
    params: { severity: high, summary: "C2 playbook failed on {{ alert.host }}" }
```

Compared with the initial version, every step checks that the data exists, critical assets go through an approval, and any failure pages the on-call.

## 11. Everything as code: IaC, history and rollback

The following are versioned the Git way, in an exportable internal repository:

- Sigma and YARA rules;
- Sysmon configurations, Defender settings (exclusions, ASR), App Control policies;
- Tetragon TracingPolicies and YARA-X configurations;
- exclusions, the honeytoken table, playbooks and circuit breakers;
- the thresholds and configuration of the policy validator.

Every change keeps its author (user or AI), the diff, the justification (the AI's reasoning), the originating alert, the validator's decision and the approver if any. Rollback is possible in one click, change by change or to a given date; the agent then reapplies the restored configuration and confirms it has been applied.

**Deploying changes.** Every endpoint configuration change is deployed in rings (pilot, then general) with an observation period, like updates (section 16).

### Everything as code (IaC)

Git is the source of truth for the whole platform. The interface, the CLI and the AI never write directly to the configuration: they produce a commit, or a merge request when human approval is required.

| Layer | What is provided |
| --- | --- |
| Deployment | Helm charts, Docker Compose, deb, rpm and msi packages, Ansible roles, OpenTofu and Terraform modules for AWS, Azure, GCP, OVHcloud, Scaleway and Proxmox |
| Platform configuration | Official OpenTofu and Terraform provider, and declarative YAML files: modules, connectors, roles, tenants, retention, circuit breakers, every other module setting (hot-reloaded, see below) |
| Security content | Sigma and YARA rules, ASR, App Control, TracingPolicies, exclusions, SCA policies, honeytokens, playbooks, parsers, forensic artefacts, GRC frameworks |
| Agents | Policies per endpoint group, selected by tags, with no manual configuration on the endpoint |

- **Plan, then apply.** `xdrctl plan` shows the gap between the repository and the real state, `xdrctl apply` applies it; the OpenTofu provider offers the same cycle. The apply is a live reload, never a restart (see "Live reconfiguration").
- **Validation in continuous integration.** Schemas, Sigma lint, policy validator (section 8), playbook simulation, detection tests on the test endpoints. A merge request that breaks a test cannot be merged.
- **Drift detection.** Any gap between the real state, including on endpoints, and the repository is reported, then corrected automatically if the policy says so. A Defender exclusion added by hand on a workstation is thus detected and removed.
- **Secrets.** Never in Git: only references to the vault (Vault, OpenBao), or files encrypted with SOPS.
- **Environments.** The same repository serves pre-production and production, with promotion by branch or by tag.
- **Multi-tenant.** One folder or repository per tenant, inheriting from a common base.
- **Read-only mode.** The interface can be configured to accept no changes: everything then goes through Git.

### Live reconfiguration

Every setting of every module and agent lives in a file that can be versioned in Git, and is applied without restart.

- **Files are the source of truth.** No setting exists only in a database, a form or a running process; the API, the interface, `xdrctl` and the AI write files (a commit or a merge request), never live state alone.
- **Reload.** A module watches its configuration files and also reloads on `SIGHUP` and on `xdrctl apply`. It parses and validates the new version strictly, swaps it atomically, keeps serving the old version when the new one is invalid, and audits every reload (applied or refused, with the diff, through the `xdrctl plan` cycle).
- **Covered without restart.** Modules, connectors, roles, tenants, retention, rules, policies, exclusions, playbooks, rate limits, OIDC settings, TLS certificates and keys (new handshakes use the new pair) and log levels.
- **Single exception.** The listening address and port of a socket, documented per module, until a socket handover exists.
- **Agents.** They receive their policy files over the agent channel, apply them without a service restart, then confirm the applied version (rollback above).

### Community library

- Content packages (rules, playbooks, SCA policies, parsers, connectors, forensic artefacts, threat sheets) published in a public registry, versioned and signed.
- Imported into the repository by reference, with a pinned version, like software dependencies.
- New versions arrive as an automatic merge request, with the diff and the detection tests replayed.

## 12. Platform security

A platform that can run commands on every endpoint is a prime target: compromising it is equivalent to compromising the whole fleet. It is therefore designed with its own threat model.

| Threat | Measures |
| --- | --- |
| Theft of an administrator account | Mandatory MFA (TOTP or WebAuthn), SSO, short sessions, alert on unusual login |
| Abuse of the remote shell or of actions | Dedicated role, dual approval on critical assets, full recording, quotas |
| Compromised server driving the agents | Commands signed by an offline key or an HSM for sensitive actions; the agent refuses any unsigned or replayed command |
| Booby-trapped update (supply chain) | Reproducible builds, Sigstore signing, published SBOM, verification by the agent before installation, deployment rings |
| Theft of connector secrets | Secrets vault (Vault or OpenBao), encryption at rest, minimal rights per connector, rotation |
| Leak between tenants (MSSP) | Indexes, encryption keys and roles separated per tenant, automated isolation tests |
| Manipulation of the AI | Guardrails of section 8 |
| Exposed data | TLS encryption everywhere, encryption at rest of ClickHouse and backups |
| Tampering with the audit trail | Append-only audit log, hash-chained, exportable to a third-party SIEM |
| Misuse of the RMM | Only signed scripts from Git, dual approval of mass executions, recorded sessions, user consent for remote control |

**Hardening.** Minimal container images, running without root, administration interfaces not exposed to the Internet by default.

**Process.** Vulnerability disclosure policy, bug bounty programme from the first public v1, external security audit before version 1.0 and at every major version.

### Code quality

The Rust code follows the project coding rules, written in English like all the content of the repository. Their key points:

- **Code**: no `unsafe` outside two isolated system interface crates (Windows API, eBPF probes), reviewed by two people and documented block by block, no possible panic (`unwrap`, `expect`, direct indexing forbidden), a single exit point per function, neither recursion nor `break`, no magic numbers, no global mutable state, existing crates preferred to home-made code.
- **Tests**: 100 % line and branch coverage, module by module, without any exclusion; error paths are covered by injecting failing dependencies.
- **Single gate**: a pre-commit hook chains `rustfmt`, `clippy`, `custom_lint`, `cargo llvm-cov` and `coverage_gate`. The `custom_lint` (rules Clippy does not cover) and `coverage_gate` (branch coverage threshold) tools are part of the project to be developed.
- **Git**: one-line commits, one coherent change per commit, never a direct push to `main`.

## 13. Interface

| Section | Content |
| --- | --- |
| **Dashboard** | Protection state, effective mode of each endpoint (full, reduced, degraded), AI mode, blind spots |
| **Hunting** | ClickHouse SQL queries (optional experimental KQL dialect), live osquery, entity graph, per-entity timeline, natural language hunting, automatic hunt packs |
| **Alerts** | Alert queue sorted by risk score, AI investigation, verdict and confidence, cases and case templates, observables and analysers, response actions, ransomware recovery, forensic hunts, CyberChef, reported phishing, out-of-band crisis room, reports |
| **Rules** | Sigma, YARA, Sysmon, ASR, App Control, TracingPolicies, FIM, exclusions (with expiry), MITRE coverage, continuous testing, migration from other SIEMs, history |
| **AI review** | Pending suggestions, sample of verdicts to review, quality statistics, validator refusals |
| **Endpoints** | Inventory, discovered unmanaged devices, state of agents and sensors, blocking capabilities, configuration (SCA), adaptive hardening, patches, encryption, browser extensions, devices, restore snapshots, containers, vulnerabilities, honeytokens and honeypots, hardened protection mode, policies, actions |
| **RMM** | Scripts and executions, patches and rings, software catalogue, desired state of devices, remote shell, remote desktop and recorded sessions, mobile devices |
| **Monitoring** | Metrics and dashboards, alert rules and forecasts, synthetic checks, traces and profiles, application health, service map |
| **On-call** | Schedules, escalation policies, notifications, silences and maintenance windows |
| **Status page** | Public status page configuration, SLA and SLO reports |
| **Infrastructure** | Site collectors, network devices, hardware health, containers, Kubernetes and virtualisation, discovery |
| **CMDB** | Assets and relationships, business services, life cycle, licences, change history, synchronisation state |
| **Exposure** | Risk score per entity, critical assets, attack paths, choke points, recommendations ranked by number of paths closed, AD and Entra ID posture and audit (change history, GPOs, rollback), leaked credentials, external attack surface, cloud and Kubernetes posture, backups |
| **Connectors** | Detection sources and action connectors, requested rights, health state, assisted import of new sources, connector generation from OpenAPI |
| **Threat intel** | Feeds, IOCs, scoring, expiry, retroactive matches, emerging threat sheets, campaigns and actors |
| **Automation** | YAML playbooks, simulation, circuit breakers, execution history, pending approvals |
| **GRC** | Frameworks, automatically evaluated controls, evidence, risk register, action plans, scheduled automatic reports |
| **Optional modules** | DNS, DHCP, WAF and reverse proxy, NDR (packet capture, network files), RMM, CMDB, always visible; those that are not configured appear in a distinct colour |
| **Identity** | Users, groups, OIDC and SAML applications, MFA, access policies adapted to risk and device posture, active sessions, authentication logs |
| **Administration** | AI configuration and budget, RBAC, SSO, multi-tenant, retention, platform audit, backups, Git repository, configuration drift, community library |

The interface is a client of the documented REST API (OpenAPI), just like the `xdrctl` CLI and the OpenTofu provider: no function is reserved to it. It displays every module, including those not yet installed or configured: these appear in a distinct colour, with what they provide and the IaC configuration snippet that enables them. **UI rule.** No third-party component with its own graphical interface reaches a user: the consoles and admin pages of Zitadel, MinIO, the CrowdSec console, Stork, the RustDesk client and every metrics, tracing or on-call tool are disabled or never exposed. Metrics charts, traces, profiles, remote desktop and the status page are all rendered by Ostyr's interface. It offers no no-code editor, and every change it allows produces a commit or a merge request (section 11). It is available in French and English.

### Log readability and ease of investigation

The goal: an analyst understands an event in a few seconds, without knowing the source or the schema, and traces a whole attack without writing a query.

**Reading an event.**

- **Plain-language summary** generated deterministically from the ECS fields, per event type, without AI: for example "jdupont launched `powershell.exe` (encoded command) from `WINWORD.EXE` on PC-042". The raw view and the ECS view stay one click away.
- **Automatically decoded values**: base64-encoded PowerShell, common obfuscated strings, command lines split into arguments, Windows error codes and event IDs translated, SIDs converted to account names, access rights in plain text.
- **Readable formats**: timestamps in the analyst's time zone with UTC on hover, rounded sizes and durations, URLs and domains defanged on display (`hxxps://example[.]com`) to avoid accidental clicks.
- **Consistent fields**: the same field name for the same notion, whatever the source, and a searchable field dictionary with their description and examples.
- **Highlighting**: in an alert, the fields that triggered the rule are highlighted, with the rule's explanation and the associated MITRE technique.

**Context displayed next to every value.**

- Threat intel (badge, source, score, date), prevalence (on how many machines this hash or domain has been seen, and since when), first appearance in the fleet.
- CMDB for machines (owner, criticality, business service), directory for users (department, manager, privileged groups), geolocation and ASN for IPs.
- Risk score of the entity and recent alerts concerning it.

**Tracing an attack.**

- **One-click pivot** on any value (hash, IP, domain, user, machine, process): filter, exclude, open the entity's page, its timeline, its alerts and its cases.
- **Interactive process tree**, with the network connections, files and registry keys of each process.
- **Session reconstruction**: everything a user did since logging on, linked by the session identifier.
- **Lateral movement chain**: following an account or a process from one machine to another, in a single view.
- **Incident timeline** built from the events pinned by the analyst or the AI, exportable into the report.
- **Next-step suggestions** for each alert type: what to check, which queries to run, as ready-to-run queries.

**Sharing and resuming.**

- Direct link to an exact view (query, period, filters, selected event), restricted to authorised people.
- Saved searches versioned in Git like the rest of the configuration.
- CSV and JSON export of any result, logged.

**Logs of the platform itself.** Module logs are structured (JSON through `tracing`), in English, with constant fields (module, tenant, request identifier, duration, result), so that an incident on the platform is as easy to investigate as a security incident.

### GRC section in detail

The GRC section turns the data the platform already collects into compliance evidence and periodic reports, with no manual entry for technical controls.

**Built-in frameworks.** NIS 2 (article 21 measures), ISO 27001:2022 (annex A), DORA for the financial sector, GDPR (articles 32 to 34), the ANSSI IT hygiene guide, CIS Controls v8. Each control is linked to the data sources that allow it to be evaluated. Custom frameworks can be imported in YAML and are versioned like the rest of the configuration (section 11).

**Automatic control evaluation.** Statuses are computed deterministically, never by the AI. Missing data gives the status "not assessable", never "compliant".

| Control | Data used | Example indicator |
| --- | --- | --- |
| Anti-malware protection | State of agents and sensors | Share of endpoints in full protection mode |
| Vulnerability management | osquery inventory, CVE, CISA KEV | Average time to fix KEV vulnerabilities |
| Logging and retention | Ingestion, ClickHouse TTL rules | Active sources, effective retention against required retention |
| Incident management | Incidents | Detection, response and closure times; notifications sent on time |
| Privileged access | Identity connectors | Privileged accounts without MFA, inactive accounts |
| Backups | Restore tests | Date of the last successful restore, immutability enabled, critical servers without a recent backup |
| Detection effectiveness | Atomic Red Team tests | Test success rate, MITRE coverage |
| System hardening | Security configuration assessment (SCA) | Hardening score per endpoint, failed CIS and ANSSI controls |
| Patch management | Patch management, osquery inventory | Share of patches applied on time, by severity |
| Workstation encryption | Disk encryption | Share of encrypted workstations, escrowed keys |
| Asset inventory | CMDB | Share of assets with an owner and a criticality, discovered unmanaged devices |

Possible statuses: compliant, partially compliant, non-compliant, not assessable.

**Evidence.** Each status is linked to timestamped and hashed evidence (query result, export, configuration capture), kept according to the retention policy. Organisational controls that cannot be automated (signed security policy, awareness training) receive manually uploaded evidence, with an owner and a review date.

**Risks and action plans.** Risk register (likelihood × impact) and action plans linked to the gaps, with owner, due date and follow-up. Actions can be pushed to ticketing through a connector.

**Automatic reports.**

| Report | Frequency | Recipients | Content |
| --- | --- | --- | --- |
| Executive summary | Monthly | Management, CISO | Overall posture, trend, main risks, notable incidents |
| SOC operations | Weekly | SOC team | Alerts, AI verdicts, delays, tunings applied and rolled back |
| Compliance per framework | Quarterly or on demand | CISO, auditors | Status control by control, evidence, gaps, action plan |
| Regulatory incident | For each flagged incident | DPO, CISO | Pre-filled draft for NIS 2 (early warning within 24 h, notification within 72 h, final report within one month) and GDPR (72 h) |
| MSSP customer | Monthly | MSSP customers | Summary per tenant, white-labelled |

Reports are generated in PDF and Markdown, with the data in CSV and JSON, and sent by email, Slack or Teams according to a configurable schedule.

**Role of AI.** It writes the summaries and recommendations from deterministically computed indicators. Every figure quoted links back to its source. Human review before sending is optional for internal reports and mandatory for regulatory reports.

**Access.** "Compliance manager" (management) and "auditor" (read-only) roles, plus temporary, logged sharing links for external auditors.

## 14. Optional modules: DNS, DHCP, WAF and reverse proxy, NDR, RMM, CMDB

These modules are **disabled by default** and install separately, alone or with the rest of the platform (section 4). Without them, DNS and DHCP detection relies on ingesting the logs of existing servers (section 6). The DNS, DHCP and WAF modules put the platform on the critical path of the network: they require at least two redundant instances.

### DNS module

- Filtering resolver (**Unbound** with RPZ zones generated from the ClickHouse IOC table) fed by threat intel.
- Sinkhole of malicious domains, with an information page for the user.
- Detection of DGAs and DNS tunnelling.
- **Transparent mode available**: the module can sit as a relay in front of existing resolvers (Active Directory in particular) rather than replacing them.
- **Continuity.** At least two instances; if the filtering engine fails, the resolver keeps answering without filtering (fail-open, configurable as fail-closed) and raises an alert.

### DHCP module (Kea)

- **Device discovery.** Any device without an agent that obtains a lease raises an alert.
- **IP ↔ MAC ↔ hostname history**, to find which machine had a given IP at the time of an alert.
- **Detection of rogue DHCP servers** on the network.
- **Quarantine** of a compromised machine in a dedicated scope or VLAN, combined with the switch connectors.
- **Continuity.** Kea high availability (hot-standby or load-balancing mode) mandatory; assisted migration from Windows DHCP and ISC DHCP.

### WAF and reverse proxy module

- **CrowdSec AppSec** in front of **Caddy**, the only supported reverse proxy (Traefik and HAProxy are not supported). Coraza and the **OWASP Core Rule Set** run inside CrowdSec.
- **CrowdSec collections**: `crowdsecurity/appsec-generic-rules`, `crowdsecurity/appsec-crs-inband`, `crowdsecurity/appsec-virtual-patching`, `crowdsecurity/base-http-scenarios`, `crowdsecurity/http-cve`, `crowdsecurity/http-dos`, `crowdsecurity/http-extended-context`, `crowdsecurity/caddy`, `crowdsecurity/whitelist-good-actors` and `ostyr/zitadel` (to be written: parser and brute-force scenario).
- **AppSec configs**: `crowdsecurity/appsec-default` (custom version with `pre_eval` exceptions) and `crowdsecurity/crs-inband`.
- **Community blocklist sharing** is optional and off in air-gapped mode.
- Starts in **detection mode** for 14 days, then switches to blocking with a CRS paranoia level of 1.
- Tuning by the AI subject to the same validator and the same exclusion rules as endpoints (section 8).

**Reverse proxy.** The module acts as the single entry point in front of web applications, with or without the WAF enabled:

- **TLS**: TLS 1.2 and 1.3 termination, automatic certificates through ACME (Let's Encrypt or an internal authority), automatic renewal, HSTS, optional mTLS towards clients or backends.
- **Routing** by host name, path and headers; HTTP/2, HTTP/3 and WebSocket; URL and header rewriting.
- **Load balancing** across several backends, with active and passive health checks, and automatic removal of a failing backend.
- **Upstream authentication**: an application without authentication can be protected by the built-in identity provider (section 15) or an external OIDC provider, with the same risk-adapted access rules.
- **Protection**: rate limiting per IP, per route or per user, IP allow and block lists fed by threat intel, optional geo-blocking, security headers (CSP, X-Frame-Options, Referrer-Policy).
- **Logging** of every request in ECS format, usable alone or by detection and the AI.
- **Configuration**: routes, certificates, backends and rules described in declarative files in Git (section 11), like the rest of the platform. High availability through at least two instances behind a virtual IP or a load balancer.

### NDR module

- **Zeek** (protocol metadata) and **Suricata** (signatures) sensors, on a mirror port or a TAP, deployed as a container or an appliance.
- **Full packet capture** by Suricata, in a ring buffer on local disk with a configurable retention period (for example 7 days). From an alert or an incident, extraction of the exact PCAP flow, downloadable or viewable online.
- **Network file analysis**: files extracted from traffic by Zeek and Suricata are scanned by **YARA-X** and then, if needed, by the sandbox.
- The module sees agentless devices (printers, IoT, OT) and lateral movement; its events feed correlation, network discovery and the risk score.

### RMM module

The RMM module (remote monitoring and management) uses the same agent as the EDR, with only the RMM functions enabled if it is deployed alone. It brings under a single policy what the IT team and the security team do on endpoints. Metrics, alerting and application health are specified in section 20, device management in section 21 and equipment without an agent in section 22.

- **Scripts**: signed library of PowerShell, Bash and Python scripts versioned in Git, with typed parameters, on-demand or scheduled execution, on a machine or a tag group. Results and outputs kept per execution (section 21).
- **Patch management and software deployment**: OS and third-party updates by rings and maintenance windows, and an approved software catalogue declared as code (section 21).
- **Device configuration**: system settings, registry keys, services, scheduled tasks and local accounts described as desired state, with optional automatic drift correction (section 23).
- **Remote shell and file transfer**: carried inside the agent channel. The agent opens a pseudo-terminal or reads a file on a signed command; no SSH server and no listening port exist on the device.
- **Remote desktop**: the RustDesk engine, relay-only, with an Ostyr viewer in the interface (section 21). Screen sharing through WebRTC, and RDP, SSH and VNC access through RustDesk, are not provided.
- **Agentless equipment**: switches, printers, BMCs and appliances push syslog, SNMP traps, flows and Redfish events to a site collector. SNMP or Redfish polling is an explicit opt-in per device, never applied to a managed device (section 22).
- **Remote tools**: file explorer, process and service manager, event viewer and terminal, all through the agent channel, without full remote control.
- **Power management**: Wake-on-LAN, scheduled restart and shutdown, respecting maintenance windows.
- **MSP use**: per-customer views, activity and monitoring reports per tenant.

**RMM security.** RMM tools are among the most misused by attackers. The module therefore applies strict controls, detailed in section 21:

- only signed scripts present in Git can run; a free-form command requires the dedicated role and MFA, and is recorded;
- an execution on more than 20 machines requires dual approval and goes through the circuit breakers (section 10);
- every remote shell and remote desktop session is recorded (command stream or video), timestamped and linked to a ticket or an incident;
- unapproved third-party remote control tools (AnyDesk, TeamViewer, ScreenConnect and equivalents) are detected, reported and can be blocked, because they often serve as a backdoor.

### CMDB module

The CMDB is the reference for assets and their relationships. It fills itself automatically and provides context to every other module.

- **Managed items**: workstations, servers, virtual machines, containers and pods, network devices, printers and IoT, cloud resources, SaaS applications, service accounts, certificates, installed software and licences.
- **Automatic population** from the agents (osquery), network discovery, DHCP logs, the NDR, cloud and Kubernetes connectors, Active Directory and Entra ID, and the external attack surface.
- **Reconciliation**: deduplication by identity keys (serial number, MAC address, cloud identifier, name), with a source of truth declared per attribute and a conflict log.
- **Business attributes declared as code**: owner, criticality, business service, environment, location, contract and warranty, described in YAML in Git (section 11), like the rest of the platform.
- **Relationships and business services**: dependencies between applications, servers, databases and networks, to know which service is affected when an asset is compromised or unavailable.
- **Life cycle**: ordered, in service, in maintenance, retired, destroyed; alert when a retired asset reappears on the network.
- **Software licences**: counting installations against acquired entitlements, detection of unauthorised software.
- **History** of every item: who or what changed it, when, and with what previous value.
- **Two-way synchronisation** with GLPI, NetBox, iTop and ServiceNow through connectors, for organisations that already have a CMDB. The connector uses their APIs only: their own interfaces are never deployed or exposed by the platform.

**What the CMDB brings to the other modules.** Criticality and owner feed the risk score, attack paths and circuit breakers (a critical asset is never isolated automatically). Business services give the impact of an incident. The complete inventory serves as evidence for GRC, since NIS 2 and ISO 27001 require an asset inventory.

## 15. Identity provider (OIDC and SAML)

The platform ships an identity provider based on **Zitadel** (AGPL licence, written in Go, multi-tenant, OIDC and SAML as identity provider, SCIM). It authenticates the platform's users and can optionally serve as the identity provider for all of the organisation's applications. Limit: Zitadel has no upstream SAML federation; Entra ID and Google federate through OIDC. Its specific value: access is decided taking into account what the XDR knows about the user's risk and the state of their device.

| Use | Activation | For whom |
| --- | --- | --- |
| Authentication to the platform | By default | Every deployment; an external SSO remains possible |
| Identity provider for the organisation | Option, disabled by default | Organisations without an identity provider (SMEs), or wanting access conditioned on the security state of devices |

### Protocols and functions

- **OpenID Connect** (authorisation code with PKCE, client credentials, device flow) and **SAML 2.0** (initiated by the service provider or by the identity provider).
- **SCIM 2.0** for provisioning and deprovisioning accounts in applications.
- **Federation** with Active Directory and LDAP, and **identity brokering** to Entra ID, Google Workspace or any other OIDC or SAML provider.
- **MFA**: WebAuthn and passkeys (FIDO2) first, TOTP, backup codes. No SMS by default.
- **Directory**: users, groups, roles, self-service password reset, password policy aligned with ANSSI recommendations, optional check against compromised password databases.
- **Sessions**: configurable durations, immediate central revocation, back-channel logout.
- **Multi-tenant**: a separate identity space (realm) per tenant.

### Risk-adapted access

- The **risk score** of the user and of their device (section 7) is evaluated at every authentication: above a first threshold, a second factor is requested again; above a high threshold, access is refused and an alert is created.
- **Device posture** usable as an access condition: agent present and active, full protection mode, minimum SCA hardening score. Example: sensitive applications are only accessible from a managed, healthy device.
- **Automatic account containment** (section 9) instantly revokes every session and every token issued by the identity provider.

### Detection

- All identity provider events are ingested natively: authentication failures, brute force, password spraying, repeated MFA failures, impossible login (geography), new device, token reuse, administration changes, registration of a new client application.
- **Decoy accounts** created in the directory: any authentication attempt raises a critical alert.

### Security and availability

- **Separate administration space**: platform administrators are in a realm distinct from that of the organisation's users, with WebAuthn mandatory.
- Local **break-glass accounts**, stored offline, to access the platform even if the identity provider is unavailable.
- Token **signing keys** stored in the secrets vault (section 12), with automatic rotation.
- **High availability mandatory** when it serves as the organisation's identity provider: at least 2 instances and a replicated database, because any outage blocks access to applications.
- Zitadel **updates** deployed in rings, like the other components.

## 16. 24/7 operations and foundation

- **Escalation to a human** for critical incidents: on-call and notifications with acknowledgement, reminder at 10 minutes, escalation to the next level at 30 minutes.
- **RBAC and SSO** through the built-in identity provider (section 15) or an external SSO over OIDC or SAML, predefined roles (reader, analyst, responder, administrator, auditor) and custom roles.
- **Multi-tenant** for MSSPs, with the isolation described in section 12.
- **Platform audit**: who viewed, changed or ran what, in a tamper-proof log.
- **Centralised update** of agents, sensors, rules and signatures, in rings (pilot, then general), with automatic halt of the rollout if the error rate of the pilot ring exceeds a threshold.
- **Monitoring of the platform itself**: Prometheus metrics, ClickHouse and NATS JetStream health, ingestion lag, AI queue.
- **Backup and restore** of the configuration and indexes, tested automatically.

## 17. Compliance, privacy and licences

### Privacy and labour law

- **Impact assessment (DPIA).** Workstation monitoring, UEBA on employees and the remote shell require a GDPR impact assessment. A DPIA template and a pre-filled record of processing activities are provided.
- **Information and consultation.** In France, deploying a tool that monitors employee activity requires informing employees and consulting the works council (CSE) beforehand. The documentation points this out at installation.
- **Minimisation.** No keystroke capture, email content or screenshots. Sensitive fields (command line content containing secrets, for example) can be masked before storage.
- **External AI.** Sending telemetry to an external API can be disabled; otherwise, the platform displays the provider, the processing region and the type of data sent. Personal identifiers can be pseudonymised before sending.
- **Differentiated retention.** Retention periods configurable per data type, with automatic purge.

### Reference frameworks

NIS 2, ISO 27001, DORA, GDPR, the ANSSI hygiene guide and the CIS Controls are managed in the GRC section of the interface (section 13), which evaluates the controls and produces the reports automatically.

### Component licences

Licences to be checked at every release; state known at the time of writing:

| Component | Licence | Consequence |
| --- | --- | --- |
| ClickHouse, NATS JetStream, Tetragon, vLLM, CyberChef, Caddy, Prowler, Trivy, syft, OpenTelemetry protocol and Collector libraries, guacd (Apache Guacamole proxy, agentless SSH opt-in only) | Apache 2.0 | No particular constraint |
| OpenTelemetry eBPF profiler | Apache 2.0, kernel-side eBPF programs GPLv2 | Run as a separate process on the agent |
| osquery | Apache 2.0 / GPLv2 (dual licence) | No particular constraint |
| YARA-X, Zeek, Unbound, OpenCanary, ipmitool | BSD | No particular constraint |
| lldpd | ISC | No particular constraint |
| Atomic Red Team, CrowdSec, Ollama, ProjectDiscovery tools (subfinder, naabu, httpx, nuclei), gitleaks, NanoMDM, winget | MIT | No particular constraint |
| Kea, Vector, OpenBao, OpenTofu | MPL 2.0 | Changes to the files concerned must be published |
| Suricata | GPLv2 | Run as a separate process, not linked to the platform code |
| USBGuard, smartmontools, NUT | GPLv2 or later (NUT Python scripts GPLv3 or later) | Run as separate processes, not linked to the platform code |
| Zitadel, RustDesk (`hbbs`, `hbbr` and the project build of the endpoint service), MinIO | AGPL-3.0 | Separate processes; the RustDesk project build publishes its sources |
| Prometheus, VictoriaMetrics, Grafana, Grafana OnCall, Jaeger, Tempo, Parca, nmap, WSUS | Not used | Excluded by the component rules (section 4): own interface, extra durable state or non-compatible licence |
| Vulnerability and baseline data: OSV, NVD, CISA KEV, EPSS, ANSSI hygiene guide, DISA STIGs | OSV: one licence per source database (CC BY 4.0, CC0, Apache 2.0, CC BY-SA 4.0 and, for Chainguard, CC BY-NC-ND 4.0); public domain (NVD, STIGs); CC0 (KEV); free of charge with no licence text published (EPSS); Etalab Open Licence 2.0 (ANSSI) | Data, not code; attribution kept; feeds verified at download; OSV sources under a non-commercial or no-derivatives licence are not ingested |
| Apple APNs and MDM protocol, Android Management API | Vendor services under their terms | Services used through their public APIs, no component redistributed; prerequisites in section 19 |
| Sysmon | Sysinternals licence (freeware) | Redistribution forbidden: downloaded from Microsoft |
| Microsoft Defender | Proprietary, included in Windows | Advanced features (custom IOCs, ASR reports) reserved for Defender for Endpoint licences |
| HashiCorp Vault | BSL | Not chosen by default |
| Packer | BSL | Development tool only, never distributed, so the licence is acceptable; builds the KVM lab images, Windows included |
| CIS Benchmarks content | CIS licence (CC BY-NC-SA 4.0) | SCA policies written by the project, quoting only CIS recommendation numbers; full content used only if the customer brings it |

**Platform licence.** Choice: **AGPL-3.0-only** for every Ostyr component, the endpoint agent included (owner decision of 2026-11-02, protection against a proprietary SaaS takeover). Contributions under DCO (section 19).

## 18. Technical points of attention

### Windows

- **Sysmon observes but blocks almost nothing.** Behavioural blocking relies on Defender (ASR, Controlled Folder Access, Network Protection), App Control and the reactive kill. The latter acts after the process has started, so later than on Linux with Tetragon.
- **Free Defender does not handle custom IOCs.** They are enforced by other means (section 7).
- **Tamper Protection.** When it is active, some Defender settings are locked. It is necessary to test precisely what the agent can change through PowerShell (`Set-MpPreference`) depending on whether the device is managed by Intune, by GPO or unmanaged, and to document the behaviour in each case.
- **Third-party antivirus.** It switches Defender to passive mode. Its presence is detected at onboarding and the endpoint is displayed with reduced protection.
- **Sysmon volume.** It depends entirely on the configuration. An overly broad configuration overloads the endpoint and ClickHouse: it is the first thing to tune, starting from a proven baseline.
- **App Control.** A badly built policy can prevent legitimate applications from starting. Every deny policy is first deployed in audit mode on the pilot ring.

### Linux

- **Blocking depends on the kernel.** Tetragon's SIGKILL works on most recent kernels. System call override requires `CONFIG_BPF_KPROBE_OVERRIDE`. BPF-LSM requires kernel 5.7 or later with `lsm=bpf` at boot, which is not the default on several distributions. The agent chooses the best available mode (section 5).
- **Older kernels.** Below 5.4, the reduced mode (partial eBPF, reactive blocking) is clearly reported. No non-eBPF sensor is used on Linux.
- **On-access YARA-X scanning is resource-hungry.** It is limited to the sensitive directories defined by the machine's role, and its consumption is monitored.
- **Immutable containers and Kubernetes nodes.** On distributions without a classic package manager (Talos, Bottlerocket, Flatcar), the agent is deployed as a DaemonSet and FIM relies on the reference image.

### General

- **Honeytokens must not get in anyone's way.** They must disrupt neither users nor legitimate tools (backup, indexing, third-party antivirus). These tools are identified at onboarding and their access to the decoys is filtered by signed process.
- **Volume can explode.** FIM and telemetry generate a huge number of events; agent-side filtering and aggregation are mandatory and the volume budget per endpoint is monitored.
- **Clock.** Correlation assumes synchronised clocks; the agent measures the drift relative to the server and corrects timestamps when needed.

## 19. Out of scope and open questions

### Out of scope for v1

- **Custom macOS Endpoint Security client**: the v1 macOS agent uses `eslogger` and the unified log (section 21).
- **Browser RDP and VNC to servers** through a gateway: remote access goes through the agent channel and the relay-only remote desktop (section 21).
- **Remote control of iOS and iPadOS devices**: Apple allows screen sharing only.
- **DLP**, beyond detection of network exfiltration.
- **PPL protection and ELAM driver** on Windows.
- **Windows Server 2012 R2 and earlier.**
- **Integration of Defender for Endpoint** and Defender for Business (API, IOCs, isolation).
- **Visual or no-code editor** for playbooks, rules or connectors, by choice: everything remains versioned code (section 11).
- **Mandatory central service**: no module may depend on another to start (section 4).

### Open prerequisites for the owner

These actions depend on accounts only the owner holds and must be done before release of the functions that need them.

- **Apple Developer ID** for signing and notarising the macOS agent (section 21).
- **APNs MDM certificate** for Apple mobile device management (section 21).
- **Android Enterprise enrolment** with the Android Management API (section 21).

### Decisions on the open questions

| Question | Decision | Why, and when to revisit it |
| --- | --- | --- |
| Platform licence | **AGPL-3.0-only for every component, the endpoint agent included.** Contributions under DCO, without a CLA. | One licence for the whole repository keeps the rules simple. The AGPL prevents a vendor from reselling the platform as closed SaaS without contributing its changes back. The DCO reassures contributors: no relicensing is possible. |
| Stream correlation engine | **Lightweight in-house engine in Rust**, built into the backend services, reading NATS JetStream or the internal buffer, with persistent on-disk state and checkpoints. It implements Sigma correlation rules (event count, value count, temporal sequences). | Flink requires a JVM and a dedicated cluster, incompatible with the all-in-one profile, and would mean maintaining two engines. To be revisited if the need exceeds 50,000 events/s or requires complex windows: Flink would then become an option of the distributed profile. |
| Language of the agent and services | **Rust**, for the agent as well as the backend services (stream engine, relay, shared module core). Third-party sensors stay in their original language (Tetragon in Go, osquery in C++) and are driven through their APIs. | No garbage collector: predictable reaction time for the reactive kill and a small memory footprint, in line with the budget of section 3 and the lightweight modules. Memory safety, essential for an agent running with the highest privileges. Suitable ecosystem: **aya** to write agent-specific eBPF probes in Rust alongside Tetragon, tonic for gRPC, windows-rs for the Windows APIs, YARA-X embedded directly as a library, and a single static binary that is easy to distribute. Trade-off: more demanding development and a smaller contributor pool than Go. |
| Tamper Protection | **Never disable it.** On unmanaged devices, the agent drives exclusions, ASR, Controlled Folder Access and Network Protection through `Set-MpPreference`. On devices managed by Intune or GPO, the agent switches to **read-only** on Defender and produces the configuration to apply in the management tool. | Tamper Protection mainly protects real-time protection, cloud protection and behaviour monitoring; exclusions are only locked when they are managed by Intune. Writing locally over a central policy would create conflicts. A test bench before going into production is still needed to confirm each setting. |
| AI evaluation thresholds | **Recall ≥ 90 % on malicious alerts, and ≤ 1 % of malicious alerts classified as benign or false positive.** Corpus of at least 500 alerts. | The major risk is not one alert too many but an attack classified as benign, which can lead to an exclusion. Corpus built from public datasets (OTRF Security-Datasets, Splunk attack\_data, EVTX-ATTACK-SAMPLES), Atomic Red Team replays on the test endpoints and benign alerts labelled by the pilots. Thresholds revisited after the first deployments. |
| Circuit breaker values | **Fixed values of section 10, plus a relative rule: never more than 2 % of the fleet isolated at the same time.** Adjustable per tenant. | Absolute values alone are too permissive for 50 workstations and too strict for 10,000. Recalibration is done by replaying the pilots' history in simulation mode, without risk. |
| Defender for Endpoint connector | **No.** The platform only uses the Defender Antivirus included in Windows, even when a Defender for Endpoint or Defender for Business licence exists. | A single operating mode for every customer: less code and fewer tests, no dependency on a Microsoft API or licence. IOCs remain enforced as described in section 7. If Defender for Endpoint is already managed by Intune, the agent stays read-only on Defender (Tamper Protection row) to avoid conflicts. |


## 20. IT monitoring and observability

These functions belong to the monitoring, on-call and status page modules (section 4). They share the rules below with sections 21 to 23.

**Common rules for sections 20 to 23.**

- **Settings are files.** Every threshold, schedule, check, baseline, catalogue, ring, route and policy introduced here is a file in Git, reloaded without restart as described in section 11 "Live reconfiguration"; an invalid file is refused and the previous version kept, and the reload is audited.
- **Headless components.** No component named here exposes its own interface; every screen is Ostyr's (section 13).
- **State.** Each subsection names where its state lives: ClickHouse, PostgreSQL, NATS JetStream, MinIO or Git, never a new store.
- **Bounded inputs.** Every input from an agent, a collector, a device or an external API is bounded in size and count before it is buffered, and every wait on a peer has a deadline.
- **Tenants.** Every item carries its tenant and is invisible to the others.

### Metrics pipeline

- **What it does.** The agent samples host metrics (CPU per core and pressure, memory and swap, disk I/O and space and inodes, network counters, temperature and fan sensors, OOM kills, reboots with their cause, uptime, system call counts through eBPF) and sends them on the agent channel. Applications and services can push metrics in OTLP to the agent or the platform.
- **Components.** The agent's own collectors, with osquery tables and the eBPF probes of section 5; the agent channel; Vector and NATS JetStream for transport; ClickHouse for storage. The OpenTelemetry protocol is the only external format; no Prometheus, VictoriaMetrics or Grafana.
- **State.** ClickHouse. Raw samples roll up by materialised views into 1 minute, 1 hour and 1 day tables, each with its own TTL and storage policy (targets in section 3).
- **Requirements.**
  - The sampling interval and the list of metrics per role are declared in the agent policy; a change applies without a service restart.
  - A metric has a name, a unit, a type (gauge, counter, histogram) and labels; the number of series per tenant and the cardinality of each label are capped, and the excess is dropped and counted, not silently ignored.
  - The query layer picks the finest table that satisfies the requested range and step; a test shows that a 30 day query never reads the raw table.
  - A silent device (no sample for three intervals) raises an "absence" alert; a clock drift is corrected before storage (section 18).
  - Agent samples are buffered with the 72 hour offline buffer of section 5 and sent in order, with sequence counters.
  - The data is exported in OTLP and ECS for third-party tools (section 4).

### Metric alerting and forecasting

- **What it does.** Alert rules on metrics: threshold, rate of change, absence, comparison to a baseline (seasonal, per entity), and forecasts such as time to disk full and capacity trend. The alerts join the same queue as security alerts.
- **Components.** The stream correlation engine (section 19) for streaming rules, and scheduled ClickHouse queries for forecasts and baselines; the on-call module for delivery. No external alert manager.
- **State.** Rules in Git; alert state and baselines in ClickHouse (small tables) and PostgreSQL (alert lifecycle).
- **Requirements.**
  - A rule file holds the query, the condition, the duration it must hold (for), the severity, the labels and the runbook link; the rule set is tested on recorded series in continuous integration.
  - Disk-full forecasting uses a linear fit over a declared window and states the projected date and its confidence; a test checks a known ramp.
  - Alert flapping is limited by hysteresis and by the duration condition; an alert that stays resolved for a declared time closes itself.
  - Alerts are deduplicated by fingerprint (rule and labels) and linked to the CMDB asset and business service (section 14).
  - Rules respect maintenance windows (below).

### On-call

- **What it does.** Routes every IT and security alert to the right person: schedules and rotations, escalation policies, notification channels, acknowledgement, silences, deduplication and grouping, and maintenance windows.
- **Components.** In-house module. Channels are connectors: SMTP, webhook, Microsoft Teams, Slack, ntfy and an SMS provider (section 6). No Grafana OnCall or other third-party on-call tool.
- **State.** PostgreSQL for the alert lifecycle (open, acknowledged, escalated, resolved) and the notification log; schedules, policies, routes and silences as files in Git.
- **Requirements.**
  - The first notification leaves within 30 seconds of the alert at the 95th percentile (section 3).
  - An unacknowledged alert escalates at the declared delay to the next level; the escalation time is driven by a clock injected in tests.
  - Schedules support time zones, rotations, overrides and holidays; a time-zone change over a daylight saving switch is tested.
  - A failing channel falls back to the next channel of the policy and is reported; no alert is lost when every channel fails (it stays open and visible).
  - A silence and a maintenance window have an author, a reason and an expiry; a silence with no expiry is refused.
  - Acknowledgement and resolution from a channel use a signed, single-use, expiring link; the link carries no secret reusable elsewhere.
  - Every notification, acknowledgement and silence is audited.

### Synthetic checks and certificate expiry

- **What it does.** Active checks of services as a user would see them: HTTP(S) with status, content and latency, TCP connect, ICMP, DNS resolution, and TLS handshake with the certificate chain and expiry, run from the platform and from site collectors.
- **Components.** In-house checks in the backend services and in the site collector; certificate data feeds the lifecycle of section 23.
- **State.** Check definitions in Git; results in ClickHouse.
- **Requirements.**
  - A check has an interval, a timeout, a number of consecutive failures before alerting, and the locations that run it; an alert needs failures from the declared number of locations.
  - Checks reach only targets declared in files, or in the CMDB for internal services; a check cannot be pointed at an arbitrary address by an API caller outside the declared scope (server-side request forgery protection: private, link-local and metadata addresses are refused unless declared).
  - Certificate expiry alerts at declared thresholds (30, 14 and 7 days by default).
  - The results are bounded in size (response bodies are never stored beyond a capped excerpt).

### Status page and SLA reports

- **What it does.** A public or private status page per business service, with current state, incidents and history, and SLA and SLO reports (availability, error budget) computed from checks and incidents.
- **Components.** In-house, served by Ostyr behind the reverse proxy (section 14); no Statuspage-like third-party software.
- **State.** PostgreSQL for incidents and messages; availability measures in ClickHouse; the page layout and components in Git.
- **Requirements.**
  - The public page is unauthenticated: it serves pre-rendered content only, exposes no internal name, address or detail beyond what the owner declared, is rate limited per source before any other work, and keeps serving a static copy when the backend is down.
  - Publishing an incident or a state change needs an authenticated role; automatic state changes follow declared rules and can be overridden.
  - The SLA computation excludes declared maintenance windows and states its method; a test replays a known outage and checks the figure.
  - Reports are generated on a schedule and can be exported (PDF and CSV).
  - The status page is on its own failure domain: its outage does not depend on the platform it reports on when deployed with the relay profile.

### Tracing/APM and profiling

- **What it does.** Distributed traces from applications in OTLP, with service maps and latency and error breakdowns, and continuous CPU profiling of every process through eBPF, linked to traces and to metrics.
- **Components.** OpenTelemetry protocol ingestion in the backend services; the OpenTelemetry eBPF profiler on the Linux agent, run as a separate process; ClickHouse storage. No Jaeger, Tempo or Parca.
- **State.** ClickHouse (traces and profile samples with their own TTL and sampling rules); profiler settings in the agent policy.
- **Requirements.**
  - Trace and profile ingestion is bounded per tenant (spans per second, span size, attributes per span); excess is dropped and counted.
  - Head and tail sampling rules are declared in files; error traces are kept at a higher rate.
  - The profiler stays within the agent CPU budget of section 3 and is disabled automatically when the budget is exceeded, with an alert.
  - Symbolisation of binaries uses local symbol files and never sends binaries to a third party.
  - A trace links to the logs and metrics of the same service and time range.

### Application health

- **What it does.** The health of what runs on the device: services and daemons, scheduled tasks and cron jobs (last run, result, duration), databases (availability, replication lag, connections, slow queries), NTP drift, queue depth and application probes (a declared command or endpoint that returns a status).
- **Components.** osquery tables and agent probes; database checks use read-only accounts through connectors; no additional component on the device.
- **State.** ClickHouse for measures; probe and expectation definitions in Git.
- **Requirements.**
  - A service expectation (should run, should be enabled) is a file; a failed or flapping service alerts with its last log lines (bounded).
  - A scheduled task that did not run within its expected window alerts.
  - NTP drift above a declared threshold alerts and is shown with the correction of section 18.
  - Probes execute only commands from signed files in Git, with a timeout and an output cap.
  - Database credentials are read-only and held in the secrets files; they never appear in a result, a log or an error.

## 21. Endpoint and device management

These functions belong to the RMM and MDM modules. They are the highest-risk part of the platform: every command is signed, checked by the agent (section 12) and audited, and the rules of "RMM security" (section 14) apply to all of them. Every flow is initiated by the device: no command port is opened on it.

### Scripts

- **What it does.** A library of PowerShell, Bash and Python scripts that run on demand, on a schedule or from a playbook, on one device or a tag group.
- **Components.** The agent command channel; signing by the platform; Git for the library.
- **State.** Scripts and parameters in Git; execution results in ClickHouse; execution state in PostgreSQL.
- **Requirements.**
  - Only a script whose signature and digest match a version merged in Git runs; the agent verifies the signature before launching it.
  - Parameters are typed and validated (string, integer, enumeration, path) against a schema, and passed as arguments, never concatenated into a shell string.
  - A run has a timeout, an output size cap and a resource limit; the output is stored per execution and redacted for declared secret patterns.
  - A run on more than 20 devices needs dual approval and passes the circuit breakers (section 10).
  - A free-form command needs the dedicated role and MFA, and is recorded in full.
  - A command replayed or expired is refused by the agent (anti-replay nonce and expiry).

### Patch management

- **What it does.** Inventories missing OS and third-party updates and applies them by rings (pilot, then groups) inside maintenance windows, with reboot handling, health checks and automatic stop when a ring fails.
- **Components.** Native mechanisms on the device: apt and dnf and zypper on Linux, the Windows Update Agent API and winget on Windows, `softwareupdate` on macOS. No WSUS and no other patch server.
- **State.** Rings, windows and policies in Git; patch state per device in PostgreSQL; history in ClickHouse.
- **Requirements.**
  - Updates come only from the vendor repositories the policy names, with the vendor signature checked by the package manager; an internal mirror is allowed for isolated networks.
  - A ring starts only when the previous ring is healthy for the declared soak time; failures above a threshold stop the rollout through the circuit breakers (section 10).
  - A device never reboots outside its maintenance window unless the policy says so; a user prompt precedes a workstation reboot.
  - A failed update rolls back when the package manager allows, otherwise raises an alert with the log.
  - Patch status feeds vulnerability management (section 23) and the risk score.
  - Every command is signed and audited.

### Software deployment

- **What it does.** An approved catalogue of applications that can be installed, updated and uninstalled on devices or groups, with staged rollout.
- **Components.** winget and MSI on Windows, the native package manager on Linux, pkg and App Store volume mechanisms on macOS; MinIO or the repository hosts the packages.
- **State.** Catalogue in Git (name, source, version policy, digest, publisher); deployment state in PostgreSQL; packages in MinIO.
- **Requirements.**
  - Only signed packages from the catalogue install; the agent verifies the signature and the pinned digest before execution.
  - A rollout is staged by rings like patches and stops on failure.
  - An uninstall removes only what the catalogue names.
  - Installed software that is not in the catalogue is reported to the CMDB licence counting (section 14).

### Remote shell and file transfer

- **What it does.** An interactive shell and file transfer to a device from the interface, without any remote-access service on the device.
- **Components.** The agent channel only: on a signed command the agent opens a pseudo-terminal or a file handle and streams it back on the existing outbound connection. No SSH server.
- **State.** Session metadata in PostgreSQL; recordings in MinIO; policy in Git.
- **Requirements.**
  - Opening a session needs the dedicated role and MFA at each opening; on critical assets (CMDB) it needs dual approval; both appear in the audit.
  - The session is recorded in full (input and output, timestamps) and linked to a ticket or an incident; a recording that cannot be written ends the session.
  - A session has an idle timeout and a maximum duration; a dead channel closes it.
  - File transfer is bounded in size, checked for malware by YARA-X when uploaded, and limited to declared paths unless approved.
  - The user of a workstation sees a banner for the whole session, except for a declared exception for machines without a user (section 17 privacy rules apply).

### Remote desktop

- **What it does.** Full screen, keyboard and mouse control of Windows, macOS, Linux and Android devices from the interface.
- **Components.** The RustDesk engine as a separate process, run in a project build with direct IP access disabled, no listening port, no hole punching and relay-only through `hbbr`; `hbbs` and `hbbr` run headless. The viewer is Ostyr's own, in the interface, speaking the RustDesk protocol over the relay. iOS and iPadOS can only share their screen (Apple restriction) and are never controlled.
- **State.** `hbbs` keeps a small peer database; it is the only extra state and is covered by backup. Session metadata in PostgreSQL, recordings in MinIO, policy in Git.
- **Requirements.**
  - The endpoint service makes only outbound connections to `hbbr`; a test scans the device for listening sockets during a session and finds none.
  - The relay accepts only sessions authorised by a short-lived token signed by the platform; a peer identifier alone gives no access.
  - The project build shows a session indicator and, on workstations, asks the user's consent; consent and indicator cannot be disabled by the viewer.
  - Session opening follows the rules of remote shell: role, MFA, dual approval on critical assets, full recording, ticket link.
  - Unapproved third-party remote tools are detected and can be blocked (section 14).

### macOS agent

- **What it does.** The common agent functions (section 5) on macOS: inventory, telemetry, state of protection.
- **Components.** osquery; `eslogger` and the unified log as telemetry sources; the application firewall, FileVault, Gatekeeper, SIP and XProtect state read from the system; launchd for supervision.
- **State.** As on the other agents: local encrypted buffer; server side as sections 4 and 20.
- **Requirements.**
  - v1 uses no custom Endpoint Security client (it needs an Apple entitlement); the agent states its reduced mode like the older Linux kernels (section 5).
  - The agent package is signed with an Apple Developer ID and notarised (open prerequisite in section 19).
  - The agent runs with the permissions macOS grants through a configuration profile deployed by MDM or by hand; a missing permission is detected and displayed as a blind spot.
  - Scripts, patches, software, remote shell and remote desktop work as on the other systems, through the same signed commands.

### Mobile devices (MDM)

- **What it does.** Enrolment, inventory, configuration, compliance, lock and wipe of iOS, iPadOS and Android devices; their posture feeds access decisions (section 15).
- **Components.** Apple MDM through APNs with NanoMDM (MIT, headless, PostgreSQL storage) as the engine; Android Enterprise through the Android Management API. Both are outbound-only from the device and the platform.
- **State.** PostgreSQL; profiles and policies in Git.
- **Requirements.**
  - The platform keeps no listening port on the device; commands travel through the vendors' push channels.
  - The APNs MDM certificate and the Android Enterprise enrolment are owner prerequisites (section 19); their keys are held in the secrets files and rotated without restart.
  - Enrolment tokens are single-use and expire; an unenrolled or wiped device is removed from the CMDB.
  - A wipe needs approval and is audited; a lost-mode lock is available.
  - Compliance rules (encryption, passcode, OS version, jailbreak) are files; a non-compliant device is reported to the identity provider for risk-adapted access (section 15).
  - The management interface is Ostyr's; no NanoMDM or vendor console is exposed.

## 22. Infrastructure and network

### Site collector

- **What it does.** An Ostyr role installed at a remote site that receives, on the local network, what agentless equipment pushes: syslog, SNMP traps, NetFlow, sFlow and IPFIX, and Redfish events. It runs checks (section 20) and probes (section 23) from that site, buffers on disk and forwards to the platform.
- **Components.** The Ostyr agent in collector role, with Vector for syslog and flows; the agent channel outbound only.
- **State.** A bounded disk buffer on the collector; everything else on the platform.
- **Requirements.**
  - The collector opens listening ports only on the local network, for the declared protocols and sources, and none towards the Internet.
  - Peers on the LAN are unauthenticated: every message is bounded in size and rate, per source and in total before parsing, and a single source cannot exhaust the capacity left for others; an unknown source is counted and optionally dropped.
  - The disk buffer has a size cap, drops the oldest low-priority data first and alerts on saturation; a dead peer or a stalled reader never blocks reception.
  - The channel to the platform is the agent channel (section 4) with the same revocation and relay rules.
  - Its configuration (allowed sources, protocols, ports, credentials) is a file pushed over the channel and applied without restart, except the listening port, which is documented as the single exception of section 11.

### Network devices

- **What it does.** Visibility on switches, routers, firewalls, access points and printers: interface state and counters, errors, topology through LLDP and CDP, flows, configuration changes and events.
- **Components.** The site collector for traps, flows and syslog; SNMP v3 decoding in the Rust code; polling by SNMP, and SSH from the interface through `guacd`, only when enabled per device.
- **State.** Metrics and flows in ClickHouse; devices and links in the CMDB (PostgreSQL); device declarations in Git.
- **Requirements.**
  - Push is the default; SNMP polling is an explicit per-device opt-in in the device file, never applied to a device that runs an agent.
  - SNMP v3 with authentication and privacy is required; v1 and v2c are refused unless the file accepts them for a named device, with a warning in the CMDB.
  - Trap and flow volumes are bounded per device; sampling rates are respected when computing traffic.
  - LLDP and CDP data builds the topology graph with a timestamp per link; a link not seen for a declared time is marked stale.
  - Credentials live in the secrets files and never appear in a log or an error.

### Hardware health

- **What it does.** Disk SMART status and predictive failure, RAID state, IPMI and Redfish sensors (temperature, fans, power supplies, memory errors), and UPS state (battery, load, runtime) through NUT.
- **Components.** `smartmontools` and the NUT client on the agent, IPMI through `ipmitool` locally; Redfish events received by the site collector, Redfish polling opt-in per device.
- **State.** ClickHouse for measures; device declarations in Git.
- **Requirements.**
  - Hardware measures use the metrics pipeline and alert rules of section 20.
  - A predictive-failure SMART attribute or a UPS on battery raises an alert with the affected asset and business service.
  - Redfish polling uses a read-only account declared in the device file; it is opt-in and never run against a managed device.
  - Tool output is parsed strictly and bounded; an unreadable output is reported as a blind spot, not as healthy.

### Containers, Kubernetes and virtualisation

- **What it does.** Inventory and metrics of containers (Docker, containerd, CRI-O), Kubernetes clusters (nodes, pods, deployments, events) and hypervisors (Proxmox, VMware vSphere, Hyper-V), linked to the CMDB.
- **Components.** The agent and Tetragon for node and container telemetry (section 5); connectors that read the Kubernetes API and the hypervisor management APIs with read-only credentials.
- **State.** Metrics in ClickHouse; items and relationships in the CMDB (PostgreSQL); connector settings in Git.
- **Requirements.**
  - Management credentials are read-only and checked at setup: a connector that is given write rights refuses to start.
  - Containers and pods are created and retired in the CMDB from events, without leaving ghost items.
  - Container metrics carry image, pod, namespace and node labels, with the cardinality caps of section 20.
  - Immutable Kubernetes nodes use the DaemonSet deployment of section 18.

### Network discovery and service map

- **What it does.** Finds devices and services on the network and draws which service talks to which, feeding the CMDB.
- **Components.** Passive sources first: DHCP leases, the NDR, flows, ARP and LLDP tables from agents. Active probing from a site collector is opt-in per network, using MIT-licensed tools (naabu, httpx) driven by the collector; nmap is not used.
- **State.** Items and relationships in the CMDB (PostgreSQL); observed flows aggregated in ClickHouse; scope declarations in Git.
- **Requirements.**
  - Active probing runs only against ranges declared in a file, with a rate limit, and never against a range not owned by the tenant.
  - A discovered device without an agent raises the alert of section 14; a discovered service is linked to its host and to the business service when known.
  - The service map is built from observed connections with a retention bound and shows the last time each edge was seen.
  - Results are reconciled with the CMDB keys (section 14) and conflicts are logged.

## 23. Exposure, vulnerabilities and compliance

### Configuration compliance and drift

- **What it does.** Evaluates devices against baselines and reports drift; optionally corrects it.
- **Components.** osquery for evaluation; baselines as code derived from the ANSSI hygiene guide and the DISA STIGs (redistributable); CIS content only when the customer brings it, because of its licence (section 17).
- **State.** Baselines and desired state in Git; results in ClickHouse; compliance state per control in PostgreSQL for GRC.
- **Requirements.**
  - A baseline is a versioned file with controls, query, expected result, severity and framework mapping; an exception is a file with owner and expiry.
  - Correction is off by default per control and applies only through signed commands; every correction is audited and reversible.
  - Results feed the GRC controls (section 13) and the risk score.
  - A baseline change goes through the detection-style tests on a lab corpus before merge.

### Certificate lifecycle

- **What it does.** Inventories certificates and warns before expiry; renews those Ostyr manages.
- **Components.** Agents (certificate stores and service endpoints), site collectors (TLS probes), public Certificate Transparency logs for the organisation's domains; ACME for renewal where Ostyr manages the service (Caddy, section 14).
- **State.** The CMDB (PostgreSQL) holds certificates and their relationships; probe results in ClickHouse; domains and policies in Git.
- **Requirements.**
  - A certificate is identified by its fingerprint and linked to the services that present it.
  - Expiry alerts follow section 20; an unexpected certificate for an owned domain in CT logs raises a security alert.
  - ACME accounts and private keys are held in the secrets files with mode checks; keys are never logged or shipped to the CMDB.
  - A failed renewal alerts well before expiry and leaves the old certificate in place.

### Vulnerability management and obsolete versions

- **What it does.** Matches the software inventory of every device against known vulnerabilities, ranks them, and reports software past end of life.
- **Components.** Local inventory from osquery and the package managers; CVE data from OSV and the NVD, EPSS scores and the CISA KEV list loaded into ClickHouse (section 7 threat intel); end-of-life dates from a versioned table; external attack-surface probing from a collector with naabu and nuclei (MIT). nmap is not used.
- **State.** Findings in ClickHouse and PostgreSQL; the end-of-life table and scan scopes in Git.
- **Requirements.**
  - Authenticated scanning is local: the device's own inventory is matched against CVE data; the platform never logs into a device remotely to scan it.
  - Network scanning only probes the declared external attack surface and agentless equipment, from a collector, with rate limits and scopes in files.
  - A finding carries CVE, affected package and version, fix version, EPSS, KEV status and the asset criticality; priority is computed deterministically.
  - A new KEV entry triggers matching over the whole inventory without waiting for the schedule.
  - Software past its end-of-life date raises a finding even when no CVE is known.
  - Feed downloads are verified (signature or digest) and bounded in size; an air-gapped mirror is supported.

### Device control

- **What it does.** Controls USB and removable storage devices and browser extensions on endpoints.
- **Components.** Microsoft Defender device control on Windows, USBGuard on Linux, osquery extension tables, and browser enterprise policies.
- **State.** Policies as allow and deny lists in Git; events in ClickHouse; the CMDB lists extensions per device.
- **Requirements.**
  - Rules match by class, vendor and product identifiers, and serial number for allowed items; a default mode of audit precedes any blocking.
  - A blocked or unknown device raises an event with the user and device identity.
  - Extensions are inventoried with identifier, version, permissions and source; those not on the allow list are reported and blocked where the browser policy permits.
  - Exceptions have an owner and an expiry.

### Secret scanning and SBOM

- **What it does.** Finds secrets left in files and repositories and builds the software bill of materials of images, packages and directories.
- **Components.** gitleaks (MIT) for secrets and syft (Apache 2.0) for SBOMs, run by the agent and by a scheduled job; SBOMs are matched with the vulnerability data above.
- **State.** Findings in PostgreSQL; SBOMs in MinIO in CycloneDX or SPDX format; scan scopes and rules in Git.
- **Requirements.**
  - A secret finding stores the location, the rule and a masked excerpt; the secret itself and any hash of it never reach storage, a log or an error.
  - Scans are bounded by file size and count and skip declared paths.
  - An SBOM is signed, versioned per artefact and diffed between versions.
  - A finding in a repository raises an alert with the owner from the CMDB.

### Cloud and SaaS posture and cost

- **What it does.** Checks the configuration of cloud accounts and SaaS tenants and follows cloud spending.
- **Components.** Connectors (section 6) with read-only API credentials; Prowler and Trivy for posture checks (section 17); billing exports loaded into ClickHouse.
- **State.** Findings in PostgreSQL; billing data in ClickHouse; account declarations in Git.
- **Requirements.**
  - Credentials are read-only and verified at setup; a connector given write rights refuses to start.
  - Posture findings map to GRC controls (section 13) and appear in the Exposure screen.
  - Cost data is aggregated per account, service, tag and business service; a budget file raises alerts on spending and on an abnormal daily change.
  - Billing exports are bounded in size and loaded idempotently.
