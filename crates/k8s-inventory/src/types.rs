use crate::error::ParseError;
use crate::limits::Limits;
use crate::model::Page;
use std::borrow::Cow;
use std::collections::BTreeMap;


pub type BorrowedLabels<'a> = BTreeMap<Cow<'a, str>, Cow<'a, str>>;


pub type LabelsAndExtra<'a> = (BorrowedLabels<'a>, usize);


pub type PageParser<Item> = fn(&[u8], &Limits, usize) -> Result<Page<Item>, ParseError>;
