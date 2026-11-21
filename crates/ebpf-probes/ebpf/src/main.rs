#![no_std]
#![no_main]

use aya_ebpf as _;


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: the crate holds no reachable panicking construct, which the denied panic, arithmetic and indexing lints enforce; the verifier still checks memory safety.
    unsafe { core::hint::unreachable_unchecked() }
}
