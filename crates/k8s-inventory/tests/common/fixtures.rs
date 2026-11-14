use serde_json::{json, Value};
use std::error::Error;


pub const UID_TAIL: usize = 12;


pub const UID_PREFIX: &str = "00000000-0000-4000-8000-";


pub fn uid(tag: &str) -> String {
    let hex = tag.bytes().map(|byte| format!("{byte:02x}")).collect::<String>();
    let tail = hex.chars().rev().take(UID_TAIL).collect::<Vec<_>>().into_iter().rev().collect::<String>();
    format!("{UID_PREFIX}{tail:0>UID_TAIL$}")
}


pub fn pod(name: &str, uid_tag: &str) -> Value {
    json!({
        "metadata": {
            "name": name,
            "namespace": "default",
            "uid": uid(uid_tag),
            "creationTimestamp": "2024-05-01T10:00:00Z",
            "labels": {"app": "web", "app.kubernetes.io/name": "nginx"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": "web-1"}]
        },
        "spec": {"nodeName": "node-a", "containers": [{"image": "nginx:1.27"}, {"image": "busybox:1"}]},
        "status": {"phase": "Running"}
    })
}


pub fn node(name: &str, uid_tag: &str) -> Value {
    json!({
        "metadata": {"name": name, "uid": uid(uid_tag)},
        "status": {
            "nodeInfo": {"kubeletVersion": "v1.30.2+k3s1", "osImage": "Ubuntu 24.04 LTS"},
            "addresses": [{"type": "InternalIP", "address": "10.0.0.5"}, {"type": "Hostname", "address": "node-a"}]
        }
    })
}


pub fn list(kind: &str, items: Vec<Value>) -> Vec<u8> {
    json!({"kind": kind, "apiVersion": "v1", "items": items}).to_string().into_bytes()
}


pub fn set(value: &mut Value, pointer: &str, new: Value) -> Result<(), Box<dyn Error>> {
    *value.pointer_mut(pointer).ok_or("no such path")? = new;
    Ok(())
}
