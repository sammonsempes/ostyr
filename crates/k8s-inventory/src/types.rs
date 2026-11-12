use std::borrow::Cow;
use std::collections::BTreeMap;


pub type BorrowedLabels<'a> = BTreeMap<Cow<'a, str>, Cow<'a, str>>;


pub type LabelsAndExtra<'a> = (BorrowedLabels<'a>, usize);
