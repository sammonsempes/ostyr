//! A model of the Windows layered device installation restrictions, read from the rendered artefact, to prove the render against `evaluate`.

use crate::limits::{ALLOW_DEVICE_IDS, ALLOW_INSTANCE_IDS, DEFAULT_BLOCK_VALUE, DENY_DEVICE_IDS, ENABLED, RESTRICTIONS_KEY, STORAGE_CLASS};
use crate::model::{Devnode, UsbDevice, WindowsPolicy};


const HID_CLASS: &str = "03";


/// The value `name` under the restrictions key is the DWORD 1.
pub fn flag_set(policy: &WindowsPolicy, name: &str) -> bool {
    policy
        .values
        .iter()
        .any(|value| value.key == RESTRICTIONS_KEY && value.name == name && value.data == ENABLED)
}


/// A list is read only while its enabling DWORD is 1; ids compare case-insensitively.
pub fn list_has(policy: &WindowsPolicy, list: &str, id: &str) -> bool {
    let key = format!("{RESTRICTIONS_KEY}\\{list}");
    flag_set(policy, list) && policy.values.iter().any(|value| value.key == key && value.data.eq_ignore_ascii_case(id))
}


/// Layers, highest first: instance-ID allow, device-ID prevent (it beats an allow of the same layer), device-ID allow, removable default.
pub fn windows_installs(policy: &WindowsPolicy, node: &Devnode) -> bool {
    let matches = |list: &str| node.hardware_ids.iter().any(|id| list_has(policy, list, id));
    if list_has(policy, ALLOW_INSTANCE_IDS, &node.instance_id) {
        true
    } else if matches(DENY_DEVICE_IDS) {
        false
    } else if matches(ALLOW_DEVICE_IDS) {
        true
    } else {
        !(flag_set(policy, DEFAULT_BLOCK_VALUE) && node.removable)
    }
}


pub fn node(hardware_id: String, instance_id: String, removable: bool) -> Devnode {
    Devnode {
        hardware_ids: vec![hardware_id],
        instance_id,
        removable,
    }
}


/// The device nodes between the port and interface `index`: the parent (always removable), a `MI_` child when the device is composite, then the class driver child (`USBSTOR` or `HID`).
pub fn chain_nodes(device: &UsbDevice, index: usize, composite: bool, child_removable: bool) -> Vec<Devnode> {
    let base = format!(
        "USB\\VID_{}&PID_{}",
        device.vendor.to_ascii_uppercase(),
        device.product.to_ascii_uppercase()
    );
    let serial = device.serial.clone().unwrap_or_else(|| "5&0".to_string());
    let parent = node(base.clone(), format!("{base}\\{serial}"), true);
    let interface = format!("{base}&MI_{index:02X}");
    let composite_child = composite.then(|| node(interface.clone(), format!("{interface}\\7&{index}"), child_removable));
    let class = device.interfaces.get(index).map(|(class, _, _)| class.as_str());
    let class_child = match class {
        Some(STORAGE_CLASS) => Some(node(
            "USBSTOR\\GenDisk".to_string(),
            format!("USBSTOR\\DISK\\{serial}&0"),
            child_removable,
        )),
        Some(HID_CLASS) => Some(node(
            format!("HID\\VID_{}&PID_{}", device.vendor, device.product),
            format!("HID\\{index}"),
            child_removable,
        )),
        _ => None,
    };
    std::iter::once(parent).chain(composite_child).chain(class_child).collect()
}


/// A function works only when every node from the port to its driver installs.
pub fn function_installed(policy: &WindowsPolicy, chain: &[Devnode]) -> bool {
    chain.iter().all(|devnode| windows_installs(policy, devnode))
}
