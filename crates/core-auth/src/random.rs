use crate::error::AuthError;
use crate::types::RandomFn;


pub fn os_random(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(buffer)
}


pub fn random_array<const LENGTH: usize>(random: RandomFn) -> Result<[u8; LENGTH], AuthError> {
    let mut bytes = [u8::MIN; LENGTH];
    random(&mut bytes)?;
    Ok(bytes)
}
