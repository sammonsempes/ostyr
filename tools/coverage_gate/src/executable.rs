use crate::error::GateError;
use std::iter::successors;
use syn::{Expr, ImplItem, Item, TraitItem};


const WINDOWS_ONLY: &str = "windows";


const LIVE_ONLY: &str = "feature = \"ebpf-live\"";


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


pub fn is_windows_only(attribute: &syn::Attribute) -> bool {
    matches!(&attribute.meta, syn::Meta::List(list) if list.path.is_ident("cfg") && list.tokens.to_string() == WINDOWS_ONLY)
}


pub fn is_live_only(attribute: &syn::Attribute) -> bool {
    matches!(&attribute.meta, syn::Meta::List(list) if list.path.is_ident("cfg") && list.tokens.to_string() == LIVE_ONLY)
}


/// `in_boundary` is true for a file of the eBPF boundary crate, the only place where a file gated on `ebpf-live` is not counted.
pub fn has_executable_code(text: &str, in_boundary: bool) -> Result<bool, syn::Error> {
    syn::parse_file(text).map(|file| executable_in(&file, in_boundary))
}


pub fn executable_in(file: &syn::File, in_boundary: bool) -> bool {
    let uncompiled = file
        .attrs
        .iter()
        .any(|attribute| is_windows_only(attribute) || (in_boundary && is_live_only(attribute)));
    all_items(file).into_iter().any(is_code) && !uncompiled
}


pub fn all_items(file: &syn::File) -> Vec<&Item> {
    let top: Vec<&Item> = file.items.iter().collect();
    successors(Some(top), |level| {
        let next: Vec<&Item> = level.iter().flat_map(|item| children(item)).collect();
        (!next.is_empty()).then_some(next)
    })
    .flatten()
    .collect()
}


/// A `#[path]` module could pull a skipped file into a counted one, so the gate refuses it in every scanned source.
pub fn has_path_module(text: &str) -> Result<bool, syn::Error> {
    syn::parse_file(text).map(|file| path_module_in(&file))
}


pub fn path_module_in(file: &syn::File) -> bool {
    all_items(file)
        .into_iter()
        .any(|item| matches!(item, Item::Mod(module) if module.attrs.iter().any(|attribute| attribute.path().is_ident("path"))))
}


/// What one read and one parse of a source file say: `(declares a #[path] module, has executable code)`.
pub fn inspect_source(path: &std::path::Path, in_boundary: bool) -> Result<(bool, bool), GateError> {
    let text = std::fs::read_to_string(path).map_err(|source| GateError::ReadSource {
        path: path.to_path_buf(),
        source,
    })?;
    let file = syn::parse_file(&text).map_err(|source| GateError::ParseSource {
        path: path.to_path_buf(),
        source,
    })?;
    Ok((path_module_in(&file), executable_in(&file, in_boundary)))
}
