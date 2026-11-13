use serde_json::{json, Value};


pub fn permissions(paths: &[(&str, &[(&str, u64)])]) -> Vec<u8> {
    let map = paths
        .iter()
        .map(|(path, privileges)| {
            let inner = privileges
                .iter()
                .map(|(name, flag)| ((*name).to_owned(), json!(flag)))
                .collect::<serde_json::Map<_, _>>();
            ((*path).to_owned(), Value::Object(inner))
        })
        .collect::<serde_json::Map<_, _>>();
    json!({"data": map}).to_string().into_bytes()
}
