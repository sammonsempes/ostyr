use crate::types::TestResult;


const FIRST_CALL_RESULT: u32 = 2;


const SECOND_CALL_RESULT: u32 = 5;


struct Info {
    value: u32,
}


struct Data {
    info: *mut Info,
    state: u32,
}


struct Guard {
    data: Box<Data>,
    info: Box<Info>,
}


fn call_through(data_pointer: *mut Data) -> u32 {
    // SAFETY: the pointer was taken from the live data box of the guard, whose `info` pointer was taken from the guard's own info box.
    let data = unsafe { &mut *data_pointer };
    data.state += 1;
    // SAFETY: `info` was derived from the info box held by the same guard and nothing moved or reborrowed that box since.
    let info = unsafe { &mut *data.info };
    info.value += 1;
    info.value + data.state
}


fn build() -> Guard {
    Guard {
        data: Box::new(Data {
            info: std::ptr::null_mut(),
            state: 0,
        }),
        info: Box::new(Info { value: 0 }),
    }
}


impl Drop for Guard {
    fn drop(&mut self) {
        let data_pointer: *mut Data = &mut *self.data;
        assert_eq!(call_through(data_pointer), SECOND_CALL_RESULT);
    }
}


#[test]
fn the_reordered_setup_keeps_both_pointers_valid_under_miri() -> TestResult {
    let mut guard = build();
    guard.data.info = &mut *guard.info;
    let data_pointer: *mut Data = &mut *guard.data;
    assert_eq!(call_through(data_pointer), FIRST_CALL_RESULT);
    assert_eq!(guard.data.state, 1);
    guard.data.state += 1;
    Ok(())
}
