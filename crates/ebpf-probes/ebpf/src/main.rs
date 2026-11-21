#![no_std]
#![no_main]

use aya_ebpf as _;


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: the eBPF verifier rejects any program that reaches a panic path, so this point is unreachable in a loaded program.
    unsafe { core::hint::unreachable_unchecked() }
}
