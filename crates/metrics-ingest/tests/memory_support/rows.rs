use crate::measure::assemble;
use crate::memory_support::framed;
use crate::memory_support::{POINTS, RESOURCE, VALUE};


const KEY: u8 = 0x0a;


const STRING: u8 = 0x0a;


const ATTRIBUTES: u8 = 0x0a;


const POINT_ATTRIBUTES: u8 = 0x3a;


const NUMBER_VALUE: u8 = 0x31;


const POINT_VALUE: i64 = 1;


const DOUBLE_VALUE: u8 = 0x21;


fn pair(tag: u8, index: usize, key_width: usize, value_width: usize, double: Option<f64>) -> Vec<u8> {
    let key = format!("{index:0>width$}", width = key_width);
    let value = if value_width == 0 {
        String::new()
    } else {
        format!("{index:0>width$}", width = value_width)
    };
    let any = match double {
        Some(number) => [DOUBLE_VALUE].into_iter().chain(number.to_le_bytes()).collect::<Vec<u8>>(),
        None => framed(STRING, value.as_bytes()),
    };
    framed(tag, &[framed(KEY, key.as_bytes()), framed(VALUE, &any)].concat())
}


fn labels(tag: u8, count: usize, key_width: usize, value_width: usize, double: Option<f64>) -> Vec<u8> {
    (0..count).flat_map(|index| pair(tag, index, key_width, value_width, double)).collect()
}


pub fn request(points: usize, count: usize, on_resource: bool, key_width: usize, value_width: usize, double: Option<f64>) -> Vec<u8> {
    let point_labels = if on_resource {
        Vec::new()
    } else {
        labels(POINT_ATTRIBUTES, count, key_width, value_width, double)
    };
    let value = [NUMBER_VALUE].into_iter().chain(POINT_VALUE.to_le_bytes()).collect::<Vec<u8>>();
    let one_point = framed(POINTS, &[point_labels, value].concat());
    let resource = if on_resource {
        framed(RESOURCE, &labels(ATTRIBUTES, count, key_width, value_width, double))
    } else {
        Vec::new()
    };
    assemble(points, &resource, &[], |_| one_point.clone())
}
