use crate::devices::MAX_DEVICES;
use crate::load::MAX_FILE_ENTRIES;
use core_config::error::ConfigError;
use thiserror::Error;


/// No variant carries text taken from a device file: only a file label, a position and a fixed field name.
#[derive(Debug, Error)]
pub enum DeviceError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file:?}: too many elements")]
    TooManyElements { file: String },
    #[error("{file:?}: invalid document")]
    InvalidDocument { file: String },
    #[error("{directory:?}: more than {} devices in all", MAX_DEVICES)]
    TooManyDevicesInAll { directory: String },
    #[error("{file:?}: device #{index}: invalid `{field}`")]
    Invalid { file: String, index: usize, field: &'static str },
    #[error("{file:?}: device #{index}: name already declared for this tenant")]
    DuplicateName { file: String, index: usize },
    #[error("{file:?}: device #{index}: address already claimed by another device of this tenant")]
    DuplicateAddress { file: String, index: usize },
    #[error("{file:?}: not a regular file")]
    NotRegular { file: String },
    #[error("{directory:?}: more than {} entries", MAX_FILE_ENTRIES)]
    TooManyEntries { directory: String },
}
