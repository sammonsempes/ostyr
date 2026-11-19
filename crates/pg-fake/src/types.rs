use std::sync::Arc;


pub type Shape = (Vec<i32>, Vec<Vec<Option<Vec<u8>>>>);


pub type Handler = Arc<dyn Fn(&str) -> crate::fake::Reply + Send + Sync>;
