use crate::error::GateError;
use std::iter::successors;
use syn::{Expr, ImplItem, Item, TraitItem};


pub fn is_code(item: &Item) -> bool {
    match item {
        Item::Fn(_) => true,
        Item::Impl(block) => block.items.iter().any(|member| matches!(member, ImplItem::Fn(_))),
        Item::Trait(block) => block
            .items
            .iter()
            .any(|member| matches!(member, TraitItem::Fn(method) if method.default.is_some())),
        Item::Const(constant) => matches!(*constant.expr, Expr::Closure(_)),
        Item::Static(variable) => matches!(*variable.expr, Expr::Closure(_)),
        _ => false,
    }
}


pub fn children(item: &Item) -> &[Item] {
    match item {
        Item::Mod(module) => module.content.as_ref().map_or(&[], |(_, items)| items.as_slice()),
        _ => &[],
    }
}


pub fn has_executable_code(text: &str) -> Result<bool, syn::Error> {
    let file = syn::parse_file(text)?;
    let top: Vec<&Item> = file.items.iter().collect();
    Ok(successors(Some(top), |level| {
        let next: Vec<&Item> = level.iter().flat_map(|item| children(item)).collect();
        (!next.is_empty()).then_some(next)
    })
    .flatten()
    .any(is_code))
}


pub fn file_has_executable_code(path: &std::path::Path) -> Result<bool, GateError> {
    let text = std::fs::read_to_string(path).map_err(|source| GateError::ReadSource {
        path: path.to_path_buf(),
        source,
    })?;
    has_executable_code(&text).map_err(|source| GateError::ParseSource {
        path: path.to_path_buf(),
        source,
    })
}
