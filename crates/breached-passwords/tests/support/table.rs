use breached_passwords::model::HASH_BYTES;
use data_encoding::HEXUPPER;


const MULTIPLIER: u128 = 6_364_136_223_846_793_005_000_000_007;


const INCREMENT: u128 = 1_442_695_040_888_963_407;


const SEED: u128 = 42;


pub fn entries(lines: usize) -> Vec<([u8; HASH_BYTES], u64)> {
    let mut state = SEED;
    let mut hashes: Vec<[u8; HASH_BYTES]> = (0..lines)
        .map(|_| {
            state = state.wrapping_mul(MULTIPLIER).wrapping_add(INCREMENT);
            state.to_be_bytes()
        })
        .collect();
    hashes.sort();
    hashes.dedup();
    hashes.into_iter().zip(1u64..).collect()
}


pub fn render(entries: &[([u8; HASH_BYTES], u64)], eol: &str) -> String {
    entries
        .iter()
        .map(|(hash, count)| format!("{}:{count}{eol}", HEXUPPER.encode(hash)))
        .collect()
}
