/// Interface class, subclass and protocol, each two lowercase hexadecimal digits as the kernel reports them.
pub type InterfaceTriple = (String, String, String);


/// Extension id to its policy entry, a sorted map so the rendered bytes are deterministic.
pub type ExtensionSettings = std::collections::BTreeMap<String, serde_json::Value>;
