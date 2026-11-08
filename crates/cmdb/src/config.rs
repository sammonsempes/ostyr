use crate::impact::BUSINESS_SERVICE_ATTRIBUTE;
use crate::model::{Asset, AssetKind, Attribute, Criticality, Lifecycle, Relationship};
use crate::types::{KeyMap, TruthMap};
use core_config::error::ConfigError;
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


pub fn load_cmdb(path: &Path) -> Result<CmdbConfig, ConfigError> {
    load_file(path)
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
