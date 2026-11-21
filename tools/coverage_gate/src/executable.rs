use crate::error::GateError;
use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
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


const PAIR: usize = 2;


const TRIPLE: usize = 3;


const INCLUDE_FORM: &str = "include!";


const INCLUDE_PROTO_FORM: &str = "include_proto! with a path-like argument";


const CFG_ATTR_PATH_FORM: &str = "path inside cfg_attr or a macro";


pub fn token_streams(root: TokenStream) -> Vec<Vec<TokenTree>> {
    let top = vec![root.into_iter().collect::<Vec<_>>()];
    successors(Some(top), |level| {
        let next: Vec<Vec<TokenTree>> = level
            .iter()
            .flatten()
            .filter_map(|tree| match tree {
                TokenTree::Group(group) => Some(group.stream().into_iter().collect()),
                _ => None,
            })
            .collect();
        (!next.is_empty()).then_some(next)
    })
    .flatten()
    .collect()
}


pub fn is_word(tree: &TokenTree, word: &str) -> bool {
    matches!(tree, TokenTree::Ident(ident) if ident == word)
}


pub fn names_path(group: &proc_macro2::Group) -> bool {
    group
        .stream()
        .to_string()
        .split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .any(|word| word == "path")
}


pub fn starts_with_path(group: &proc_macro2::Group) -> bool {
    group.delimiter() == Delimiter::Bracket && group.stream().into_iter().next().is_some_and(|first| is_word(&first, "path"))
}


pub fn is_plain_name(group: &proc_macro2::Group) -> bool {
    let text = group.stream().to_string();
    text.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).is_some_and(|name| {
        !name.is_empty()
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '.' || character == '_')
    })
}


pub fn refused_pair(pair: &[TokenTree]) -> Option<&'static str> {
    match pair {
        [name, TokenTree::Punct(bang)] if is_word(name, "include") && bang.as_char() == '!' => Some(INCLUDE_FORM),
        [name, TokenTree::Group(group)] if is_word(name, "cfg_attr") && names_path(group) => Some(CFG_ATTR_PATH_FORM),
        [TokenTree::Punct(hash), TokenTree::Group(group)] if hash.as_char() == '#' && starts_with_path(group) => Some(CFG_ATTR_PATH_FORM),
        _ => None,
    }
}


pub fn refused_triple(triple: &[TokenTree]) -> Option<&'static str> {
    match triple {
        [name, TokenTree::Punct(bang), TokenTree::Group(group)]
            if is_word(name, "include_proto") && bang.as_char() == '!' && !is_plain_name(group) =>
        {
            Some(INCLUDE_PROTO_FORM)
        }
        _ => None,
    }
}


/// The first refused form in the token tree of a source, at every nesting depth and inside macro bodies.
pub fn hidden_form(file: &syn::File) -> Option<&'static str> {
    token_streams(file.to_token_stream()).iter().find_map(|trees| {
        let pair = trees.windows(PAIR).find_map(refused_pair);
        pair.or_else(|| trees.windows(TRIPLE).find_map(refused_triple))
    })
}


pub fn has_hidden_form(text: &str) -> Result<Option<&'static str>, syn::Error> {
    syn::parse_file(text).map(|file| hidden_form(&file))
}


/// What one read and one parse of a source file say: `(declares a #[path] module, a refused form, has executable code)`.
pub fn inspect_source(path: &std::path::Path, in_boundary: bool) -> Result<(bool, Option<&'static str>, bool), GateError> {
    let text = std::fs::read_to_string(path).map_err(|source| GateError::ReadSource {
        path: path.to_path_buf(),
        source,
    })?;
    let file = syn::parse_file(&text).map_err(|source| GateError::ParseSource {
        path: path.to_path_buf(),
        source,
    })?;
    Ok((path_module_in(&file), hidden_form(&file), executable_in(&file, in_boundary)))
}
