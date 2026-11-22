#![no_std]
#![no_main]

use aya_ebpf as _;


#[cfg(feature = "panic-check")]
extern "C" {
    fn ebpf_panic_reached() -> !;
}


#[cfg(not(feature = "panic-check"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: no panic path survives in the shipped object, which the check build proves on every commit (lab/ebpf-no-panic.sh); the verifier still checks memory safety.
    unsafe { core::hint::unreachable_unchecked() }
}


#[cfg(feature = "panic-check")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: the symbol is never defined, so the check build links only when no panic path is reachable; this object is never loaded.
    unsafe { ebpf_panic_reached() }
}
