//! Type aliases of the host crate.

use crate::btf::{TaskOffsets, MEMBER_WORDS};


pub type Walked = (usize, Option<TaskOffsets>);


pub type Member = [u32; MEMBER_WORDS];
