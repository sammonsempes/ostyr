/// True for the ASCII graphic characters `0x21..=0x7E`.
pub fn is_graphic(character: char) -> bool {
    character.is_ascii_graphic()
}


/// ASCII allowlist: graphic characters and single inner spaces, no leading `-`, non-empty, within the byte cap.
pub fn valid_text(text: &str, max_bytes: usize) -> bool {
    let words_ok = text.split(' ').all(|word| !word.is_empty() && word.chars().all(is_graphic));
    text.len() <= max_bytes && !text.starts_with('-') && words_ok
}
