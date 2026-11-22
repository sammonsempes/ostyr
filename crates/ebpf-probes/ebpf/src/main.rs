#![no_std]
#![no_main]

use aya_ebpf as _;


extern "C" {
    fn ebpf_panic_reached() -> !;
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: the symbol is never defined, so this call exists only in an object where a panic path survived; that object is refused by lab/ebpf-no-panic.sh and by the kernel, so it never runs.
    unsafe { ebpf_panic_reached() }
}
