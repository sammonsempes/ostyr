use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::{Hash, Hasher};


pub const UID_TAIL: usize = 12;


pub const UID_MASK: u64 = 0xffff_ffff_ffff;


pub const UID_PREFIX: &str = "00000000-0000-4000-8000-";


pub fn uid(tag: &str) -> String {
    let mut hasher = DefaultHasher::new();
    tag.hash(&mut hasher);
    format!("{UID_PREFIX}{:0>UID_TAIL$x}", hasher.finish() & UID_MASK)
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
