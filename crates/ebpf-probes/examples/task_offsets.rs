use ebpf_probes::btf::{read_task_offsets, VMLINUX_BTF_PATH};
use std::io::Write;
use std::path::Path;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let offsets = read_task_offsets(Path::new(VMLINUX_BTF_PATH))?;
    let mut stdout = std::io::stdout();
    writeln!(
        stdout,
        "task_struct.real_parent={} task_struct.tgid={}",
        offsets.real_parent, offsets.tgid
    )?;
    Ok(())
}
