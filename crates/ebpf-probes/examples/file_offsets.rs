use ebpf_probes::btf::VMLINUX_BTF_PATH;
use ebpf_probes::btf_file::read_file_offsets;
use std::io::Write;
use std::path::Path;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let offsets = read_file_offsets(Path::new(VMLINUX_BTF_PATH))?;
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{offsets:?}")?;
    Ok(())
}
