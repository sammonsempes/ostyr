#![no_std]
#![no_main]

use aya_ebpf as _;


extern "C" {
    fn ebpf_panic_reached() -> !;
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: the symbol is never defined, so this call exists only in an object where a panic path survived; lab/ebpf-no-panic.sh refuses that object. libbpf also refuses it (failed to find BTF for extern) but that depends on the object layout and the production loader is aya, so the check is the line of defence.
    unsafe { ebpf_panic_reached() }
}
