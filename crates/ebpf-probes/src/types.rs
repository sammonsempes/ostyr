//! Type aliases of the host crate.

use crate::btf::{TaskStruct, MEMBER_WORDS};


pub type Walked = (usize, Option<TaskStruct>);


pub type Member = [u32; MEMBER_WORDS];


pub type Resolved = (u32, usize);


#[derive(Clone, Copy, Debug)]
pub struct Lookup<'a> {
    pub types: &'a [u8],
    pub strings: &'a [u8],
    pub index: &'a [usize],
}


pub type ExtraType<'a> = (u32, u32, &'a [u32]);
