//! Bounded reading and strict parsing of the catalogue and assignment files.

use crate::error::CatalogueError;
use crate::limits::Limits;
use crate::model::{Assignment, Catalogue};
use crate::validate::first_problem;
use core_config::parse::parse_document;
use std::collections::BTreeSet;
use std::io::Read;


const FILE_LABEL: &str = "catalogue";


pub fn read_text<Source: Read>(reader: Source, limits: &Limits) -> Result<String, CatalogueError> {
    let mut buffer = Vec::new();
    reader
        .take((limits.max_catalogue_bytes as u64).saturating_add(1))
        .read_to_end(&mut buffer)?;
    if buffer.len() > limits.max_catalogue_bytes {
        Err(CatalogueError::TooLarge {
            limit: limits.max_catalogue_bytes,
        })
    } else {
        String::from_utf8(buffer).map_err(|_| CatalogueError::NotUtf8)
    }
}


pub fn parse_catalogue(text: &str, limits: &Limits) -> Result<Catalogue, CatalogueError> {
    if text.len() > limits.max_catalogue_bytes {
        Err(CatalogueError::TooLarge {
            limit: limits.max_catalogue_bytes,
        })
    } else {
        let catalogue: Catalogue = parse_document(text, FILE_LABEL)?;
        check_entries(&catalogue, limits).map(|()| catalogue)
    }
}


pub fn check_entries(catalogue: &Catalogue, limits: &Limits) -> Result<(), CatalogueError> {
    if catalogue.entries.len() > limits.max_entries {
        Err(CatalogueError::TooManyEntries { limit: limits.max_entries })
    } else {
        catalogue
            .entries
            .iter()
            .enumerate()
            .try_for_each(|(index, entry)| first_problem(entry).map_or(Ok(()), |field| Err(CatalogueError::InvalidEntry { index, field })))?;
        catalogue
            .entries
            .iter()
            .try_fold(BTreeSet::new(), |mut seen, entry| {
                if seen.insert(entry.name.as_str()) {
                    Ok(seen)
                } else {
                    Err(CatalogueError::DuplicateName { name: entry.name.clone() })
                }
            })
            .map(|_| ())
    }
}


pub fn parse_assignment(text: &str, limits: &Limits) -> Result<Assignment, CatalogueError> {
    if text.len() > limits.max_catalogue_bytes {
        Err(CatalogueError::TooLarge {
            limit: limits.max_catalogue_bytes,
        })
    } else {
        Ok(parse_document(text, FILE_LABEL)?)
    }
}
