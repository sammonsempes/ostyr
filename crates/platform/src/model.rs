#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::VariantArray)]
pub enum Module {
    Alerts,
    Cases,
    Cmdb,
    Risk,
    Hunts,
    Certificates,
    Oncall,
    Dhcp,
    Compliance,
    Vulnerabilities,
    RemoteShell,
    Posture,
    Status,
    Grc,
    AttackPaths,
    Playbooks,
}
