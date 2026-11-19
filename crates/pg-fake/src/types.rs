use std::sync::Arc;


pub type Shape = (usize, i32, Vec<Vec<Vec<u8>>>);


pub type Handler = Arc<dyn Fn(&str) -> crate::fake::Reply + Send + Sync>;
