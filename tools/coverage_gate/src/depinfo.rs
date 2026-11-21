use crate::error::GateError;
use crate::metadata::Package;
use crate::unscanned::{canonical_entry, out_dir_allowed, out_dir_file};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;


pub const DEPS_FLAG: &str = "--deps-dir=";


const DEP_INFO_EXTENSION: &str = "d";


const SOURCE_EXTENSION: &str = "rs";


const ENV_COMMENT: char = '#';


const ESCAPE: char = '\\';


const RULE_SEPARATOR: &str = ": ";


const PRODUCT_KINDS: [&str; 7] = ["lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro", "bin"];


#[derive(Debug, PartialEq, Eq)]
pub struct Product {
    pub package: String,
    pub target: String,
    pub root: PathBuf,
    pub manifest: PathBuf,
}


/// Splits the prerequisites of a make rule on unescaped spaces (`a\ b` is one name).
pub fn split_names(text: &str) -> Vec<String> {
    text.split(' ')
        .filter(|name| !name.is_empty())
        .fold(Vec::new(), |mut names: Vec<String>, name| {
            match names.last_mut().filter(|last| last.ends_with(ESCAPE)) {
                Some(last) => {
                    last.pop();
                    last.push(' ');
                    last.push_str(name);
                }
                None => names.push(name.to_string()),
            }
            names
        })
}


/// Every `.rs` source rustc read for one unit, from its dep-info text.
pub fn dep_info_sources(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.starts_with(ENV_COMMENT))
        .filter_map(|line| line.split_once(RULE_SEPARATOR))
        .flat_map(|(_, prerequisites)| split_names(prerequisites))
        .filter(|name| Path::new(name).extension().is_some_and(|extension| extension == SOURCE_EXTENSION))
        .collect()
}


pub fn dep_info_files(directories: &[PathBuf]) -> Result<Vec<PathBuf>, GateError> {
    let found = directories
        .iter()
        .map(|directory| {
            WalkDir::new(directory)
                .into_iter()
                .map(|walked| walked.map(walkdir::DirEntry::into_path))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(found
        .into_iter()
        .flatten()
        .filter(|path| path.is_file() && path.extension().is_some_and(|extension| extension == DEP_INFO_EXTENSION))
        .collect())
}


pub fn read_unit(root: &Path, file: &Path) -> Result<Vec<PathBuf>, GateError> {
    let text = std::fs::read_to_string(file).map_err(|source| GateError::ReadSource {
        path: file.to_path_buf(),
        source,
    })?;
    dep_info_sources(&text).iter().map(|name| canonical_entry(&root.join(name))).collect()
}


pub fn products(members: &[&Package]) -> Result<Vec<Product>, GateError> {
    members
        .iter()
        .flat_map(|package| package.targets.iter().map(move |target| (*package, target)))
        .filter(|(_, target)| target.kind.iter().any(|kind| PRODUCT_KINDS.contains(&kind.as_str())))
        .map(|(package, target)| {
            canonical_entry(&target.src_path).map(|root| Product {
                package: package.name.clone(),
                target: target.name.clone(),
                root,
                manifest: package.manifest_path.clone(),
            })
        })
        .collect()
}


pub fn judge(bases: &[PathBuf], scanned: &[PathBuf], members: &[&Package], source: &Path) -> Result<(), GateError> {
    let generated = bases.iter().find_map(|base| out_dir_file(base, source));
    let allowed = match generated {
        Some((package, name)) => out_dir_allowed(members, package, name)?,
        None => scanned.iter().any(|candidate| candidate == source),
    };
    allowed
        .then_some(())
        .ok_or_else(|| GateError::UncheckedCompiledFile { path: source.to_path_buf() })
}


pub fn in_scope(root: &Path, product: &Product, scope: &[String]) -> bool {
    scope.is_empty() || scope.iter().any(|directory| product.manifest.starts_with(root.join(directory)))
}


/// Rule 1 of T692A cycle 3: every `.rs` file rustc read for a workspace library or binary is scanned, or generated protobuf of its own `OUT_DIR`.
pub fn refuse_unchecked(root: &Path, scanned: &[PathBuf], members: &[&Package], directories: &[PathBuf], scope: &[String]) -> Result<(), GateError> {
    let wanted = products(members)?;
    if wanted.is_empty() {
        Ok(())
    } else {
        refuse_units(root, scanned, members, directories, scope, &wanted)
    }
}


pub fn refuse_units(
    root: &Path,
    scanned: &[PathBuf],
    members: &[&Package],
    directories: &[PathBuf],
    scope: &[String],
    wanted: &[Product],
) -> Result<(), GateError> {
    let bases = directories
        .iter()
        .map(|directory| canonical_entry(directory))
        .collect::<Result<Vec<_>, _>>()?;
    let units = dep_info_files(&bases)?
        .iter()
        .map(|file| read_unit(root, file))
        .collect::<Result<Vec<_>, _>>()?;
    units
        .iter()
        .filter(|unit| wanted.iter().any(|product| unit.contains(&product.root)))
        .try_for_each(|unit| unit.iter().try_for_each(|source| judge(&bases, scanned, members, source)))?;
    wanted.iter().filter(|product| in_scope(root, product, scope)).try_for_each(|product| {
        units
            .iter()
            .any(|unit| unit.contains(&product.root))
            .then_some(())
            .ok_or_else(|| GateError::MissingDepInfo {
                package: product.package.clone(),
                target: product.target.clone(),
            })
    })
}
