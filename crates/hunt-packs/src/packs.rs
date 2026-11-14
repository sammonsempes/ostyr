use crate::error::PackError;
use crate::model::{HuntPack, HuntPackFile, LoadedPack, Source};
use crate::text::valid_text;
use core_config::parse::{parse_document, read_text};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(unix))]
use std::fs::symlink_metadata;
use std::fs::{read_dir, DirEntry, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};


pub const MAX_FILE_BYTES: u64 = 1_048_576;


pub const MAX_PACKS: usize = 256;


pub const MAX_ENTRIES: usize = 256;


pub const MAX_TESTS: usize = 32;


pub const MAX_QUERY_BYTES: usize = 16_384;


pub const MAX_ID_CHARS: usize = 64;


pub const MAX_TITLE_BYTES: usize = 200;


pub const MAX_HYPOTHESIS_BYTES: usize = 1_000;


pub const MAX_CORPUS_BYTES: usize = 256;


pub const MIN_SCHEDULE_SECONDS: u64 = 300;


pub const MAX_SCHEDULE_SECONDS: u64 = 2_592_000;


pub const MIN_WINDOW_SECONDS: u64 = 60;


pub const MAX_WINDOW_SECONDS: u64 = 7_776_000;


pub const MAX_ROWS_CEILING: u64 = 10_000_000;


pub const MAX_SECONDS_CEILING: u64 = 3_600;


pub const MAX_BYTES_READ_CEILING: u64 = 107_374_182_400;


pub const TECHNIQUE_PREFIX: char = 'T';


pub const TECHNIQUE_DIGITS: usize = 4;


pub const SUBTECHNIQUE_DIGITS: usize = 3;


pub const STATEMENT_END: char = ';';


pub const TENANT_PARAM: &str = "{tenant:String}";


pub const WINDOW_START_PARAM: &str = "{window_start:DateTime64(3)}";


pub const WINDOW_END_PARAM: &str = "{window_end:DateTime64(3)}";


pub const YAML_EXTENSION: &str = "yaml";


/// Reads at most `MAX_FILE_BYTES` from `reader`, parses strictly and validates bounds; `file` only labels errors.
pub fn parse_packs(reader: &mut dyn Read, file: &str) -> Result<HuntPackFile, PackError> {
    let text = read_text(&mut Read::take(reader, MAX_FILE_BYTES + 1), file)?;
    (text.len() as u64 <= MAX_FILE_BYTES)
        .then_some(())
        .ok_or_else(|| PackError::FileTooLarge { file: file.to_string() })?;
    let pack_file = parse_document::<HuntPackFile>(&text, file)?;
    validate_pack_file(&pack_file, file)?;
    Ok(pack_file)
}


/// Opens a file for reading without following a symlink and without blocking on a pipe.
#[cfg(unix)]
pub fn open_regular(path: &Path) -> io::Result<File> {
    use rustix::fs::OFlags;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)
}


#[cfg(not(unix))]
pub fn open_regular(path: &Path) -> io::Result<File> {
    symlink_metadata(path).and_then(|found| {
        if found.is_symlink() {
            Err(io::Error::other("symbolic link"))
        } else {
            File::open(path)
        }
    })
}


/// One pack file through the handle that was checked: a symlink, a pipe or a directory is refused.
pub fn load_file(path: &Path) -> Result<HuntPackFile, PackError> {
    let file = path.display().to_string();
    let mut handle = open_regular(path).map_err(|source| core_config::error::ConfigError::Io { file: file.clone(), source })?;
    handle
        .metadata()
        .is_ok_and(|found| found.is_file())
        .then_some(())
        .ok_or_else(|| PackError::NotRegular { file: file.clone() })?;
    parse_packs(&mut handle, &file)
}


pub fn validate_pack_file(pack_file: &HuntPackFile, file: &str) -> Result<(), PackError> {
    (pack_file.packs.len() <= MAX_PACKS)
        .then_some(())
        .ok_or_else(|| PackError::TooManyPacks {
            file: file.to_string(),
            count: pack_file.packs.len(),
        })?;
    pack_file
        .packs
        .iter()
        .try_fold(BTreeSet::new(), |mut seen, pack| {
            validate_pack(file, pack)?;
            seen.insert(pack.id.as_str()).then_some(seen).ok_or_else(|| PackError::DuplicateId {
                file: file.to_string(),
                pack: pack.id.clone(),
            })
        })
        .map(|_| ())
}


pub fn validate_pack(file: &str, pack: &HuntPack) -> Result<(), PackError> {
    let clickhouse = pack.source == Source::Clickhouse;
    let checks = [
        ("id", is_pack_id(&pack.id)),
        ("title", valid_text(&pack.title, MAX_TITLE_BYTES)),
        ("hypothesis", valid_text(&pack.hypothesis, MAX_HYPOTHESIS_BYTES)),
        ("technique", is_technique(&pack.technique)),
        ("query", query_ok(&pack.query) && (!clickhouse || params_ok(&pack.query))),
        (
            "schedule_seconds",
            (MIN_SCHEDULE_SECONDS..=MAX_SCHEDULE_SECONDS).contains(&pack.schedule_seconds),
        ),
        ("window_seconds", (MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(&pack.window_seconds)),
        ("window_seconds", !clickhouse || pack.window_seconds >= pack.schedule_seconds),
        ("cost.max_rows", (1..=MAX_ROWS_CEILING).contains(&pack.cost.max_rows)),
        ("cost.max_seconds", (1..=MAX_SECONDS_CEILING).contains(&pack.cost.max_seconds)),
        ("cost.max_bytes_read", bytes_read_ok(pack.source, pack.cost.max_bytes_read)),
        ("baseline.max_matches", pack.baseline.max_matches <= MAX_ROWS_CEILING),
        ("tests", tests_ok(pack)),
    ];
    checks.iter().find(|check| !check.1).map_or(Ok(()), |check| {
        Err(PackError::Invalid {
            file: file.to_string(),
            pack: pack.id.clone(),
            field: check.0,
        })
    })
}


/// `[a-z0-9][a-z0-9_.-]{0,63}`.
pub fn is_pack_id(id: &str) -> bool {
    let mut characters = id.chars();
    id.len() <= MAX_ID_CHARS
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || matches!(next, '_' | '.' | '-'))
}


/// `T` and four digits, then optionally `.` and three digits.
pub fn is_technique(text: &str) -> bool {
    let (base, sub) = text.split_once('.').map_or((text, None), |(base, sub)| (base, Some(sub)));
    base.strip_prefix(TECHNIQUE_PREFIX)
        .is_some_and(|digits| all_digits(digits, TECHNIQUE_DIGITS))
        && sub.is_none_or(|digits| all_digits(digits, SUBTECHNIQUE_DIGITS))
}


pub fn all_digits(text: &str, count: usize) -> bool {
    text.len() == count && text.bytes().all(|byte| byte.is_ascii_digit())
}


/// Not empty, within `MAX_QUERY_BYTES`, no NUL, and a `;` only as the trailing character. A text check, not a security control.
pub fn query_ok(query: &str) -> bool {
    let body = query.trim_end().trim_end_matches(STATEMENT_END);
    let trailing = query.trim_end().len() - body.len();
    query.len() <= MAX_QUERY_BYTES && !body.trim().is_empty() && !query.contains('\0') && !body.contains(STATEMENT_END) && trailing <= 1
}


/// A clickhouse query names the tenant and both window parameters; a text check, not isolation.
pub fn params_ok(query: &str) -> bool {
    [TENANT_PARAM, WINDOW_START_PARAM, WINDOW_END_PARAM]
        .iter()
        .all(|name| query.contains(name))
}


pub fn bytes_read_ok(source: Source, bytes_read: Option<u64>) -> bool {
    match source {
        Source::Clickhouse => bytes_read.is_some_and(|bytes| (1..=MAX_BYTES_READ_CEILING).contains(&bytes)),
        Source::Osquery => bytes_read.is_none(),
    }
}


pub fn tests_ok(pack: &HuntPack) -> bool {
    pack.tests.len() <= MAX_TESTS
        && pack
            .tests
            .iter()
            .all(|case| corpus_ok(&case.corpus) && case.expect_matches <= MAX_ROWS_CEILING)
}


/// Relative path of plain segments: no leading `/` or `-`, no `.` or `..` segment, no backslash.
pub fn corpus_ok(path: &str) -> bool {
    valid_text(path, MAX_CORPUS_BYTES)
        && !path.starts_with('/')
        && !path.contains('\\')
        && path.split('/').all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}


pub fn source_name(source: Source) -> &'static str {
    match source {
        Source::Clickhouse => "clickhouse",
        Source::Osquery => "osquery",
    }
}


pub fn is_yaml(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == YAML_EXTENSION)
}


/// The path of a regular `*.yaml` entry; a symbolic link named `*.yaml` is an error, anything else is skipped.
pub fn yaml_path(candidate: io::Result<DirEntry>) -> Result<Option<PathBuf>, PackError> {
    let (path, file_type) = candidate.and_then(|found| found.file_type().map(|kind| (found.path(), kind)))?;
    (!(file_type.is_symlink() && is_yaml(&path)))
        .then_some(())
        .ok_or_else(|| PackError::Symlink {
            file: path.display().to_string(),
        })?;
    Ok((file_type.is_file() && is_yaml(&path)).then_some(path))
}


/// The `*.yaml` files of `dir` in name order; more than `MAX_ENTRIES` entries is an error.
pub fn yaml_files(dir: &Path) -> Result<Vec<PathBuf>, PackError> {
    let entries = read_dir(dir)?
        .take(MAX_ENTRIES + 1)
        .map(yaml_path)
        .collect::<Result<Vec<Option<PathBuf>>, PackError>>()?;
    (entries.len() <= MAX_ENTRIES).then_some(()).ok_or_else(|| PackError::TooManyEntries {
        dir: dir.display().to_string(),
    })?;
    let mut paths: Vec<PathBuf> = entries.into_iter().flatten().collect();
    paths.sort();
    Ok(paths)
}


/// Every pack of every `*.yaml` file of `dir`, each file validated alone, ids unique across files.
pub fn load_packs(dir: &Path) -> Result<Vec<LoadedPack>, PackError> {
    let loaded = yaml_files(dir)?.iter().try_fold(Vec::new(), |mut loaded, path| {
        let file = path.display().to_string();
        loaded.extend(load_file(path)?.packs.into_iter().map(|pack| LoadedPack { file: file.clone(), pack }));
        Ok::<Vec<LoadedPack>, PackError>(loaded)
    })?;
    loaded.iter().try_fold(BTreeMap::new(), |mut first_seen: BTreeMap<&str, &str>, item| {
        first_seen
            .insert(item.pack.id.as_str(), item.file.as_str())
            .map_or(Ok(()), |first| {
                Err(PackError::DuplicateAcrossFiles {
                    pack: item.pack.id.clone(),
                    first: first.to_string(),
                    second: item.file.clone(),
                })
            })
            .map(|()| first_seen)
    })?;
    Ok(loaded)
}
