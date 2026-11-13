use cmdb::model::{Asset, AssetKind, IdentityKey, Lifecycle};


pub fn asset_with_mac(id: &str, mac: &str) -> Asset {
    Asset {
        id: id.to_string(),
        kind: AssetKind::Printer,
        lifecycle: Lifecycle::InService,
        keys: [(IdentityKey::Mac, mac.to_string())].into_iter().collect(),
        attributes: Default::default(),
    }
}
