use crate::error::{CmdbConfigError, CmdbError};
use crate::impact::BUSINESS_SERVICE_ATTRIBUTE;
use crate::model::{Asset, AssetKind, Attribute, Criticality, Lifecycle, Relationship};
use crate::reconcile::{check_text, is_reserved_attribute, is_reserved_source, MAX_ATTRIBUTE_NAME_BYTES, MAX_VALUE_BYTES};
use crate::summary::MAX_ID_BYTES;
use crate::types::{KeyMap, TruthMap};
use core_config::load::load_file;
use serde::Deserialize;
use std::path::Path;


pub const DECLARED_SOURCE: &str = "declared";


pub const OWNER_ATTRIBUTE: &str = "owner";


pub const CRITICALITY_ATTRIBUTE: &str = "criticality";


pub const ENVIRONMENT_ATTRIBUTE: &str = "environment";


pub const LOCATION_ATTRIBUTE: &str = "location";


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredAsset {
    pub id: String,
    pub kind: AssetKind,
    pub lifecycle: Lifecycle,
    #[serde(default)]
    pub keys: KeyMap,
    pub owner: Option<String>,
    pub criticality: Option<Criticality>,
    pub business_service: Option<String>,
    pub environment: Option<String>,
    pub location: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CmdbConfig {
    #[serde(default)]
    pub sources_of_truth: TruthMap,
    #[serde(default)]
    pub assets: Vec<DeclaredAsset>,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
}


pub fn check_declared(declared: &DeclaredAsset) -> Result<(), CmdbError> {
    (!declared.id.is_empty())
        .then_some(())
        .ok_or(CmdbError::EmptyField { field: "asset id" })?;
    check_text("asset id", &declared.id, MAX_ID_BYTES)?;
    declared.keys.values().try_for_each(|value| check_text("keys", value, MAX_VALUE_BYTES))?;
    [&declared.owner, &declared.business_service, &declared.environment, &declared.location]
        .into_iter()
        .flatten()
        .try_for_each(|value| check_text("attribute value", value, MAX_VALUE_BYTES))
}


pub fn check_not_empty(field: &'static str, text: &str) -> Result<(), CmdbError> {
    (!text.is_empty()).then_some(()).ok_or(CmdbError::EmptyField { field })
}


pub fn check_relationship(relationship: &Relationship) -> Result<(), CmdbError> {
    check_not_empty("relationship from", &relationship.from)?;
    check_not_empty("relationship to", &relationship.to)?;
    check_text("relationship from", &relationship.from, MAX_ID_BYTES)?;
    check_text("relationship to", &relationship.to, MAX_ID_BYTES)
}


pub fn check_truth(attribute: &str, source: &str) -> Result<(), CmdbError> {
    check_not_empty("source of truth attribute", attribute)?;
    check_not_empty("source of truth source", source)?;
    (!is_reserved_attribute(attribute)).then_some(()).ok_or(CmdbError::ReservedName {
        field: "source of truth attribute",
    })?;
    (!is_reserved_source(source)).then_some(()).ok_or(CmdbError::ReservedName {
        field: "source of truth source",
    })?;
    check_text("source of truth attribute", attribute, MAX_ATTRIBUTE_NAME_BYTES)?;
    check_text("source of truth source", source, MAX_VALUE_BYTES)
}


/// Loads the file and refuses a declared asset, relationship or source of truth that breaks the observation caps; the error names file, index and field.
pub fn load_cmdb(path: &Path) -> Result<CmdbConfig, CmdbConfigError> {
    let config: CmdbConfig = load_file(path)?;
    config.relationships.iter().enumerate().try_for_each(|(index, relationship)| {
        check_relationship(relationship).map_err(|source| CmdbConfigError::Relationship {
            file: path.display().to_string(),
            index,
            source,
        })
    })?;
    config.sources_of_truth.iter().enumerate().try_for_each(|(index, (attribute, origin))| {
        check_truth(attribute, origin).map_err(|source| CmdbConfigError::SourceOfTruth {
            file: path.display().to_string(),
            index,
            source,
        })
    })?;
    config.assets.iter().enumerate().try_for_each(|(index, declared)| {
        check_declared(declared).map_err(|source| CmdbConfigError::Declared {
            file: path.display().to_string(),
            index,
            source,
        })
    })?;
    Ok(config)
}


pub fn to_asset(declared: &DeclaredAsset) -> Asset {
    let attributes = [
        (OWNER_ATTRIBUTE, declared.owner.clone()),
        (CRITICALITY_ATTRIBUTE, declared.criticality.map(|level| level.to_string())),
        (BUSINESS_SERVICE_ATTRIBUTE, declared.business_service.clone()),
        (ENVIRONMENT_ATTRIBUTE, declared.environment.clone()),
        (LOCATION_ATTRIBUTE, declared.location.clone()),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value.map(|text| {
            (
                name.to_string(),
                Attribute {
                    value: text,
                    source: DECLARED_SOURCE.to_string(),
                },
            )
        })
    })
    .collect();
    Asset {
        id: declared.id.clone(),
        kind: declared.kind,
        lifecycle: declared.lifecycle,
        keys: declared.keys.clone(),
        attributes,
    }
}


pub fn declared_assets(config: &CmdbConfig) -> Vec<Asset> {
    config.assets.iter().map(to_asset).collect()
}
