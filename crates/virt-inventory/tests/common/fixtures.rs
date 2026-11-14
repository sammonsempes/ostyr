use serde_json::Value;
use std::error::Error;


const GUEST: &str = r#"{"id":"KIND/VMID","type":"KIND","vmid":VMID,"name":"NAME","node":"pve","status":"running",
"maxcpu":2,"maxmem":2147483648,"maxdisk":8589934592,"template":0,"uptime":120,"cpu":0.0125}"#;


const NODE: &str = r#"{"id":"node/NAME","type":"node","node":"NAME","status":"online","maxcpu":4,"maxmem":8589934592}"#;


const STORAGE: &str = r#"{"id":"storage/NODE/NAME","type":"storage","storage":"NAME","node":"NODE","status":"available",
"shared":0,"maxdisk":42000000000,"content":"iso,vztmpl"}"#;


/// Parses JSON text; a parse error becomes a string value so a test that uses it fails on its own assertion.
pub fn value(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|error| Value::String(error.to_string()))
}


pub fn guest(kind: &str, vmid: &str, name: &str) -> Value {
    value(&GUEST.replace("KIND", kind).replace("VMID", vmid).replace("NAME", name))
}


pub fn node(name: &str) -> Value {
    value(&NODE.replace("NAME", name))
}


pub fn storage(node_name: &str, name: &str) -> Value {
    value(&STORAGE.replace("NODE", node_name).replace("NAME", name))
}


pub fn data(items: Vec<Value>) -> Vec<u8> {
    Value::Object([("data".to_owned(), Value::Array(items))].into_iter().collect())
        .to_string()
        .into_bytes()
}


pub fn set(target: &mut Value, pointer: &str, json_text: &str) -> Result<(), Box<dyn Error>> {
    *target.pointer_mut(pointer).ok_or("no such path")? = value(json_text);
    Ok(())
}
