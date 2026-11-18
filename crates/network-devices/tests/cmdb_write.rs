mod common;
#[path = "common/fake.rs"]
mod fake;


use cmdb::error::StoreError;
use cmdb::model::{Asset, AssetKind, Attribute, IdentityKey, Lifecycle, Limits};
use cmdb::reconcile::check_observation;
use common::types::TestResult;
use fake::{executor, lock, seed_server, Fake};
use network_devices::cmdb_write::{agent_host_devices, asset_kind_of, observation_of, observations, write_devices, SOURCE};
use network_devices::devices::parse_device_file;
use network_devices::model::{Device, DeviceKind, Volumes};
use std::net::{IpAddr, Ipv4Addr};


const DEVICE_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));


const EXTRA_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));


const THREE: usize = 3;


const FILE: &str = "site.yaml";


const SMALL_ASSET_CAP: usize = 2;


const LONG_NAME_BYTES: usize = 5_000;


const FILE_TEXT: &str = "devices:
  - name: core-sw1
    tenant: acme
    kind: switch
    addresses: [192.0.2.10, 192.0.2.9]
    stale_after_seconds: 900
    snmp:
      polling: true
      version: v3
      security_level: auth_priv
      auth_protocol: sha256
      priv_protocol: aes128
      credentials: acme/core-sw1.snmp
  - name: lobby-prn
    tenant: acme
    kind: printer
    addresses: [192.0.2.30]
    stale_after_seconds: 900
  - name: rack-ups
    tenant: acme
    kind: ups
    addresses: [192.0.2.31]
    stale_after_seconds: 900
  - name: core-sw1
    tenant: globex
    kind: router
    addresses: [198.51.100.1]
    agent_managed: true
    stale_after_seconds: 900
";


fn devices() -> Result<Vec<Device>, Box<dyn std::error::Error>> {
    Ok(parse_device_file(&mut FILE_TEXT.as_bytes(), FILE)?.devices)
}


fn plain_device(name: String) -> Device {
    Device {
        name,
        tenant: "acme".to_owned(),
        kind: DeviceKind::Other,
        addresses: vec![DEVICE_ADDRESS],
        agent_managed: false,
        snmp: None,
        volumes: Volumes::default(),
        stale_after_seconds: 1,
    }
}


fn asset_reporting(kind: AssetKind, address: &str) -> Asset {
    Asset {
        id: "name:x".to_owned(),
        kind,
        lifecycle: Lifecycle::InService,
        keys: Default::default(),
        attributes: [(
            "discovery.ip".to_owned(),
            Attribute {
                value: address.to_owned(),
                source: "discovery".to_owned(),
            },
        )]
        .into_iter()
        .collect(),
    }
}


fn attribute_of(device: &Device, name: &str) -> Option<String> {
    observation_of(device).attributes.get(name).cloned()
}


#[test]
fn kinds_and_attributes_map() -> TestResult {
    let found = devices()?;
    let kinds: Vec<AssetKind> = found.iter().map(|device| asset_kind_of(device.kind)).collect();
    assert_eq!(
        kinds,
        [AssetKind::NetworkDevice, AssetKind::Printer, AssetKind::Iot, AssetKind::NetworkDevice]
    );
    let all = observations(&found);
    assert_eq!(all.len(), found.len());
    let (tenant, first) = all.first().ok_or("none")?;
    assert_eq!(tenant, "acme");
    assert_eq!(first.source, SOURCE);
    assert_eq!(first.keys.get(&IdentityKey::Name).map(String::as_str), Some("netdev:core-sw1"));
    assert_eq!(first.attributes.get("network.kind").map(String::as_str), Some("switch"));
    assert_eq!(
        first.attributes.get("network.addresses").map(String::as_str),
        Some("192.0.2.10,192.0.2.9")
    );
    assert_eq!(first.attributes.get("network.snmp_polling").map(String::as_str), Some("true"));
    assert!(!first.attributes.contains_key("owner"));
    let names: Vec<Option<String>> = found.iter().map(|device| attribute_of(device, "network.kind")).collect();
    assert_eq!(
        names,
        [
            Some("switch".to_owned()),
            Some("printer".to_owned()),
            Some("ups".to_owned()),
            Some("router".to_owned())
        ]
    );
    let others = [
        (DeviceKind::Firewall, "firewall"),
        (DeviceKind::AccessPoint, "access_point"),
        (DeviceKind::Other, "other"),
    ];
    for (kind, text) in others {
        let mut device = plain_device("x".to_owned());
        device.kind = kind;
        assert_eq!(attribute_of(&device, "network.kind").as_deref(), Some(text));
        assert_eq!(attribute_of(&device, "network.snmp_polling").as_deref(), Some("false"));
        assert!(check_observation(&observation_of(&device)).is_ok());
    }
    Ok(())
}


#[tokio::test]
async fn write_then_rerun_unchanged_and_tenants_separate() -> TestResult {
    let found = devices()?;
    let fake = Fake::default();
    let exec = executor(&fake);
    let first = write_devices(&exec, &found, &Default::default(), &Limits::default()).await?;
    let acme = first.tenants.get("acme").ok_or("acme")?;
    assert_eq!((acme.created, acme.updated, acme.unchanged, acme.refused), (THREE, 0, 0, 0));
    assert_eq!(first.tenants.get("globex").ok_or("globex")?.created, 1);
    {
        let tenants = lock(&fake.tenants);
        assert_eq!(tenants.get("acme").ok_or("acme")?.assets.len(), THREE);
        assert_eq!(tenants.get("globex").ok_or("globex")?.assets.len(), 1);
        assert!(tenants.get("globex").ok_or("globex")?.assets.contains_key("name:netdev:core-sw1"));
    }
    let second = write_devices(&exec, &found, &Default::default(), &Limits::default()).await?;
    let again = second.tenants.get("acme").ok_or("acme")?;
    assert_eq!((again.created, again.updated, again.unchanged), (0, 0, THREE));
    let mut changed = found.clone();
    changed.truncate(1);
    changed.iter_mut().for_each(|device| device.addresses.push(EXTRA_ADDRESS));
    let third = write_devices(&exec, &changed, &Default::default(), &Limits::default()).await?;
    assert_eq!(third.tenants.get("acme").ok_or("acme")?.updated, 1);
    assert!(lock(&fake.scopes).iter().all(|tenant| tenant == "acme" || tenant == "globex"));
    Ok(())
}


#[tokio::test]
async fn refused_device_is_alone() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let found = vec![plain_device("ok".to_owned()), plain_device("a".repeat(LONG_NAME_BYTES))];
    let report = write_devices(&exec, &found, &Default::default(), &Limits::default()).await?;
    let acme = report.tenants.get("acme").ok_or("acme")?;
    assert_eq!((acme.created, acme.refused), (1, 1));
    Ok(())
}


#[tokio::test]
async fn cap_is_loud() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let found = devices()?;
    let limits = Limits {
        max_assets: SMALL_ASSET_CAP,
        ..Limits::default()
    };
    let result = write_devices(&exec, &found, &Default::default(), &limits).await;
    assert!(matches!(result, Err(StoreError::CapReached { .. })));
    Ok(())
}


#[tokio::test]
async fn bad_tenant_is_refused() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let mut device = plain_device("x".to_owned());
    device.tenant = "-bad".to_owned();
    let result = write_devices(&exec, &[device], &Default::default(), &Limits::default()).await;
    assert!(matches!(result, Err(StoreError::Pg(_))));
    assert!(lock(&fake.scopes).is_empty());
    Ok(())
}


#[tokio::test]
async fn agent_host_cross_check() -> TestResult {
    let fake = Fake::default();
    seed_server(&fake, "acme", "srv1", "192.0.2.30");
    seed_server(&fake, "globex", "srv2", "198.51.100.1");
    let exec = executor(&fake);
    let found = devices()?;
    let report = write_devices(&exec, &found, &Default::default(), &Limits::default()).await?;
    assert_eq!(report.tenants.get("acme").ok_or("acme")?.agent_hosts, ["lobby-prn"]);
    assert!(report.tenants.get("globex").ok_or("globex")?.agent_hosts.is_empty());
    Ok(())
}


#[test]
fn cross_check_filters() -> TestResult {
    let found = vec![plain_device("p".to_owned())];
    let server = vec![asset_reporting(AssetKind::Server, "192.0.2.99")];
    assert_eq!(agent_host_devices(&found, "acme", &server), ["p"]);
    assert!(agent_host_devices(&found, "acme", &[asset_reporting(AssetKind::Workstation, "192.0.2.98")]).is_empty());
    assert_eq!(
        agent_host_devices(&found, "acme", &[asset_reporting(AssetKind::Workstation, "192.0.2.99")]),
        ["p"]
    );
    assert!(agent_host_devices(&found, "acme", &[asset_reporting(AssetKind::Server, "not-an-address")]).is_empty());
    assert!(agent_host_devices(&found, "acme", &[asset_reporting(AssetKind::Iot, "192.0.2.99")]).is_empty());
    let mut no_attribute = asset_reporting(AssetKind::Server, "192.0.2.99");
    no_attribute.attributes.clear();
    assert!(agent_host_devices(&found, "acme", &[no_attribute]).is_empty());
    let managed: Vec<Device> = found
        .iter()
        .cloned()
        .map(|mut device| {
            device.agent_managed = true;
            device
        })
        .collect();
    assert!(agent_host_devices(&managed, "acme", &server).is_empty());
    assert!(agent_host_devices(&found, "globex", &server).is_empty());
    Ok(())
}
