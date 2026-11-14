use crate::{
    model::{violation_at, Context, Violation},
    tokens::{is_keyword, significant_tokens, Token},
    types::CallGraph,
};
use petgraph::{algo::kosaraju_scc, graphmap::DiGraphMap};
use quote::ToTokens;
use ra_ap_rustc_lexer::TokenKind;
use std::collections::{BTreeMap, BTreeSet};
use syn::{Item, ItemFn};


pub const RECURSION: &str = "recursion";


const MAX_MODULE_DEPTH: usize = 8;


const CALL_WIDTH: usize = 3;


const ALIAS_WIDTH: usize = 3;


pub fn expand_modules(items: Vec<&Item>) -> Vec<&Item> {
    items
        .into_iter()
        .flat_map(|item| match item {
            Item::Mod(module) => module.content.iter().flat_map(|(_, inner)| inner.iter()).collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}


pub fn flatten_items(items: &[Item]) -> Vec<&Item> {
    (0..MAX_MODULE_DEPTH).fold(items.iter().collect(), |current, _| expand_modules(current))
}


pub fn alias_pair(window: &[Token]) -> Option<(String, String)> {
    match window {
        [original, keyword, alias] if original.kind == TokenKind::Ident && is_keyword(keyword, "as") => {
            Some((alias.text.to_string(), original.text.to_string()))
        }
        _ => None,
    }
}


pub fn alias_map(items: &[&Item]) -> BTreeMap<String, String> {
    items
        .iter()
        .filter(|item| matches!(item, Item::Use(_)))
        .flat_map(|item| {
            let text = item.to_token_stream().to_string();
            significant_tokens(&text).windows(ALIAS_WIDTH).filter_map(alias_pair).collect::<Vec<_>>()
        })
        .collect()
}


pub fn call_name<'a>(window: &[Token<'a>]) -> Option<&'a str> {
    match window {
        [before, name, paren]
            if name.kind == TokenKind::Ident && paren.kind == TokenKind::OpenParen && before.kind != TokenKind::Dot && !is_keyword(before, "fn") =>
        {
            Some(name.text)
        }
        _ => None,
    }
}


pub fn callees(function: &ItemFn, aliases: &BTreeMap<String, String>, names: &BTreeSet<String>) -> BTreeSet<String> {
    let body = function.block.to_token_stream().to_string();
    significant_tokens(&body)
        .windows(CALL_WIDTH)
        .filter_map(call_name)
        .map(|name| aliases.get(name).map_or(name, String::as_str).to_string())
        .filter(|name| names.contains(name))
        .collect()
}


pub struct Reach<'a> {
    pub recursive: BTreeSet<&'a str>,
}


pub fn recursive_functions(graph: &CallGraph) -> Reach<'_> {
    let edges: Vec<(&str, &str)> = graph
        .iter()
        .flat_map(|(name, targets)| targets.iter().map(move |target| (name.as_str(), target.as_str())))
        .collect();
    let digraph = DiGraphMap::<&str, ()>::from_edges(edges);
    let recursive = kosaraju_scc(&digraph)
        .into_iter()
        .flat_map(|component| match component.as_slice() {
            [single] if !digraph.contains_edge(single, single) => Vec::new(),
            _ => component,
        })
        .collect();
    Reach { recursive }
}


pub struct FileItems<'a> {
    pub context: &'a Context,
    pub items: Vec<&'a Item>,
    pub aliases: BTreeMap<String, String>,
}


pub struct Located<'a, 'b> {
    pub file: &'b FileItems<'a>,
    pub function: &'a ItemFn,
}


pub fn file_items(context: &Context) -> FileItems<'_> {
    let items = flatten_items(&context.file.items);
    let aliases = alias_map(&items);
    FileItems { context, items, aliases }
}


pub fn located_functions<'a, 'b>(files: &'b [FileItems<'a>]) -> Vec<Located<'a, 'b>> {
    files
        .iter()
        .flat_map(|file| {
            file.items.iter().filter_map(move |item| match item {
                Item::Fn(function) => Some(Located { file, function }),
                _ => None,
            })
        })
        .collect()
}


pub fn recursion_in_crate(contexts: &[&Context]) -> Vec<Violation> {
    let files: Vec<FileItems> = contexts.iter().map(|context| file_items(context)).collect();
    let functions = located_functions(&files);
    let names: BTreeSet<String> = functions.iter().map(|located| located.function.sig.ident.to_string()).collect();
    let edges = functions.iter().fold(CallGraph::new(), |mut graph, located| {
        graph
            .entry(located.function.sig.ident.to_string())
            .or_default()
            .extend(callees(located.function, &located.file.aliases, &names));
        graph
    });
    let reach = recursive_functions(&edges);
    functions
        .iter()
        .filter(|located| reach.recursive.contains(located.function.sig.ident.to_string().as_str()))
        .map(|located| {
            let function = located.function;
            let start = function.sig.ident.span().start();
            violation_at(
                located.file.context,
                RECURSION,
                (start.line, start.column + 1),
                format!("function `{}` is recursive", function.sig.ident),
            )
        })
        .collect()
}
