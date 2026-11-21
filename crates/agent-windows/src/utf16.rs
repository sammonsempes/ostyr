use crate::model::{
    Utf16State, BYTE_ORDER_MARK, CARRIAGE_RETURN_UNIT, FIRST_PRINTABLE_UNIT, HIGH_SURROGATE_FIRST, HIGH_SURROGATE_LAST, LINE_FEED_UNIT,
    LOW_SURROGATE_FIRST, LOW_SURROGATE_LAST, NONCHARACTER_FFFE, NONCHARACTER_FFFF, REPLACEMENT, TAB_UNIT,
};


pub fn is_high(unit: u16) -> bool {
    (HIGH_SURROGATE_FIRST..=HIGH_SURROGATE_LAST).contains(&unit)
}


pub fn is_low(unit: u16) -> bool {
    (LOW_SURROGATE_FIRST..=LOW_SURROGATE_LAST).contains(&unit)
}


pub fn is_replaced(unit: u16) -> bool {
    let control = unit < FIRST_PRINTABLE_UNIT && ![TAB_UNIT, LINE_FEED_UNIT, CARRIAGE_RETURN_UNIT].contains(&unit);
    is_low(unit) || control || unit == NONCHARACTER_FFFE || unit == NONCHARACTER_FFFF
}


pub fn single_unit(state: &mut Utf16State, unit: u16, emit: &mut dyn FnMut(char, bool)) {
    if is_high(unit) {
        state.high = Some(unit);
    } else if is_replaced(unit) {
        emit(REPLACEMENT, true);
    } else {
        emit(char::from_u32(u32::from(unit)).unwrap_or(REPLACEMENT), false);
    }
}


pub fn push_unit(state: &mut Utf16State, unit: u16, emit: &mut dyn FnMut(char, bool)) {
    let first = !state.started;
    state.started = true;
    state.bad_order = state.bad_order || (first && unit == NONCHARACTER_FFFE);
    let pending = state.high.take();
    let paired = pending
        .filter(|_| is_low(unit))
        .and_then(|high| char::decode_utf16([high, unit]).next().and_then(Result::ok));
    let bom = first && unit == BYTE_ORDER_MARK;
    if let Some(character) = paired {
        emit(character, false);
    } else if !bom {
        pending.iter().for_each(|_| emit(REPLACEMENT, true));
        single_unit(state, unit, emit);
    }
}


pub fn decode_chunk(state: &mut Utf16State, chunk: &[u8], emit: &mut dyn FnMut(char, bool)) {
    chunk.iter().for_each(|byte| match state.carry.take() {
        Some(low) => push_unit(state, u16::from_le_bytes([low, *byte]), emit),
        None => state.carry = Some(*byte),
    });
}


pub fn stream_flawed(state: &Utf16State) -> bool {
    state.carry.is_some() || state.bad_order
}
