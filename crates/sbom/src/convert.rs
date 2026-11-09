//! SBOM to the package list `match_inventory` takes.

use crate::model::Sbom;
use vuln_match::model::Package;


/// Sorted and deduplicated; components without a mapped ecosystem or a version are left out (they are counted at parse time).
pub fn to_packages(sbom: &Sbom) -> Vec<Package> {
    let mut packages: Vec<Package> = sbom.components.iter().filter_map(|component| component.package.clone()).collect();
    packages.sort();
    packages.dedup();
    packages
}
