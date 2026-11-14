use crate::bounds::{counted_array, counted_map, map_values};
use crate::error::ParseError;
use crate::limits::{Limits, CEILING_MAX_BYTES};
use crate::model::{Finding, Findings, SkipReason, Skipped};
use crate::text::{
    severity_of, shown, status_of, valid_provider, valid_reference, MAX_ACCOUNT_BYTES, MAX_CHECK_ID_BYTES, MAX_REGION_BYTES, MAX_RESOURCE_TYPE_BYTES,
    MAX_RESOURCE_UID_BYTES,
};
use crate::types::IdentityKey;
use core_pg::scope::tenant_scope;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::Read;
use time::OffsetDateTime;


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9999;


#[derive(Deserialize, Default)]
struct RawInfo<'a> {
    #[serde(borrow)]
    uid: Option<Cow<'a, str>>,
    #[serde(borrow)]
    title: Option<Cow<'a, str>>,
    #[serde(borrow)]
    types: Option<&'a RawValue>,
}


#[derive(Deserialize, Default)]
struct RawMetadata<'a> {
    #[serde(borrow)]
    event_code: Option<Cow<'a, str>>,
}


#[derive(Deserialize, Default)]
struct RawAccount<'a> {
    #[serde(borrow)]
    uid: Option<Cow<'a, str>>,
}


#[derive(Deserialize, Default)]
struct RawCloud<'a> {
    #[serde(borrow, default)]
    account: RawAccount<'a>,
    #[serde(borrow)]
    region: Option<Cow<'a, str>>,
}


#[derive(Deserialize, Default)]
struct RawResource<'a> {
    #[serde(borrow)]
    uid: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "type")]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow)]
    namespace: Option<Cow<'a, str>>,
    #[serde(borrow)]
    labels: Option<&'a RawValue>,
}


#[derive(Deserialize, Default)]
struct RawUnmapped<'a> {
    #[serde(borrow)]
    provider: Option<Cow<'a, str>>,
    #[serde(borrow)]
    provider_uid: Option<Cow<'a, str>>,
    #[serde(borrow)]
    categories: Option<&'a RawValue>,
    #[serde(borrow)]
    depends_on: Option<&'a RawValue>,
    #[serde(borrow)]
    related_to: Option<&'a RawValue>,
    #[serde(borrow)]
    additional_urls: Option<&'a RawValue>,
    #[serde(borrow)]
    compliance: Option<&'a RawValue>,
}


#[derive(Deserialize)]
struct RawFinding<'a> {
    #[serde(borrow, default)]
    finding_info: RawInfo<'a>,
    #[serde(borrow, default)]
    metadata: RawMetadata<'a>,
    #[serde(borrow)]
    status_code: Option<Cow<'a, str>>,
    #[serde(borrow)]
    status_detail: Option<Cow<'a, str>>,
    #[serde(borrow)]
    severity: Option<Cow<'a, str>>,
    time: Option<i64>,
    #[serde(borrow)]
    resources: Option<&'a RawValue>,
    #[serde(borrow)]
    cloud: Option<RawCloud<'a>>,
    #[serde(borrow)]
    unmapped: Option<&'a RawValue>,
}


fn unparsable(_error: serde_json::Error) -> SkipReason {
    SkipReason::Unparsable
}


fn out_of_range(_error: time::error::ComponentRange) -> SkipReason {
    SkipReason::BadField
}


fn reference_of(value: Option<&str>, max_bytes: usize) -> Result<String, SkipReason> {
    value
        .filter(|text| valid_reference(text, max_bytes))
        .map(str::to_owned)
        .ok_or(SkipReason::BadField)
}


/// The finding time, refused unless its UTC year can be written back as RFC 3339 (0 to 9999).
pub fn checked_time(unix: Option<i64>) -> Result<i64, SkipReason> {
    let seconds = unix.ok_or(SkipReason::BadField)?;
    let moment = OffsetDateTime::from_unix_timestamp(seconds).map_err(out_of_range)?;
    if (MIN_YEAR..=MAX_YEAR).contains(&moment.year()) {
        Ok(seconds)
    } else {
        Err(SkipReason::BadField)
    }
}


fn resources_of<'a>(raw: &RawFinding<'a>, limits: &Limits) -> Result<Vec<RawResource<'a>>, SkipReason> {
    counted_array(raw.resources, limits.max_resources)?;
    let resources = raw
        .resources
        .map_or(Ok(Vec::new()), |value| serde_json::from_str::<Vec<RawResource>>(value.get()))
        .map_err(unparsable)?;
    resources
        .iter()
        .try_for_each(|resource| counted_array(resource.labels, limits.max_labels).map(|_count| ()))?;
    Ok(resources)
}


fn unmapped_of<'a>(raw: &RawFinding<'a>, limits: &Limits) -> Result<RawUnmapped<'a>, SkipReason> {
    counted_map(raw.unmapped, limits.max_unmapped)?;
    let unmapped = raw
        .unmapped
        .map_or(Ok(RawUnmapped::default()), |value| serde_json::from_str::<RawUnmapped>(value.get()))
        .map_err(unparsable)?;
    [unmapped.categories, unmapped.depends_on, unmapped.related_to, unmapped.additional_urls]
        .into_iter()
        .try_for_each(|list| counted_array(list, limits.max_list).map(|_count| ()))?;
    counted_map(unmapped.compliance, limits.max_frameworks)?;
    map_values(unmapped.compliance)?
        .into_iter()
        .try_for_each(|requirements| counted_array(Some(requirements), limits.max_requirements).map(|_count| ()))?;
    Ok(unmapped)
}


/// One finding, parsed alone: every collection counted first, a foreign account refused, then each field checked against its grammar.
pub fn convert_finding(raw: &RawValue, account: &str, limits: &Limits) -> Result<Finding, SkipReason> {
    let finding: RawFinding = serde_json::from_str(raw.get()).map_err(unparsable)?;
    counted_array(finding.finding_info.types, limits.max_list)?;
    let resources = resources_of(&finding, limits)?;
    let unmapped = unmapped_of(&finding, limits)?;
    let resource = resources.first().ok_or(SkipReason::BadField)?;
    let (found_account, region) = match &finding.cloud {
        Some(cloud) => (cloud.account.uid.as_deref(), cloud.region.as_deref()),
        None => (unmapped.provider_uid.as_deref(), resource.namespace.as_deref()),
    };
    if found_account.ok_or(SkipReason::BadField)? != account {
        Err(SkipReason::ForeignAccount)?;
    }
    Ok(Finding {
        uid: shown(finding.finding_info.uid.as_deref().ok_or(SkipReason::BadField)?, limits.max_text_bytes),
        check_id: reference_of(finding.metadata.event_code.as_deref(), MAX_CHECK_ID_BYTES)?,
        status: finding.status_code.as_deref().and_then(status_of).ok_or(SkipReason::BadField)?,
        severity: finding.severity.as_deref().and_then(severity_of).ok_or(SkipReason::BadField)?,
        provider: unmapped
            .provider
            .as_deref()
            .filter(|text| valid_provider(text))
            .map(str::to_owned)
            .ok_or(SkipReason::BadField)?,
        account: reference_of(found_account, MAX_ACCOUNT_BYTES)?,
        region: reference_of(region, MAX_REGION_BYTES)?,
        resource_uid: reference_of(resource.uid.as_deref(), MAX_RESOURCE_UID_BYTES)?,
        resource_type: reference_of(resource.kind.as_deref(), MAX_RESOURCE_TYPE_BYTES)?,
        time_unix: checked_time(finding.time)?,
        title: shown(finding.finding_info.title.as_deref().unwrap_or(""), limits.max_text_bytes),
        detail: shown(finding.status_detail.as_deref().unwrap_or(""), limits.max_text_bytes),
    })
}


pub fn identity_of(finding: &Finding) -> IdentityKey {
    (
        finding.provider.clone(),
        finding.account.clone(),
        finding.region.clone(),
        finding.check_id.clone(),
        finding.resource_uid.clone(),
    )
}


pub fn count_skip(skipped: &mut Skipped, reason: SkipReason) {
    match reason {
        SkipReason::Unparsable => skipped.unparsable += 1,
        SkipReason::BadField => skipped.bad_field += 1,
        SkipReason::Duplicate => skipped.duplicate += 1,
        SkipReason::ForeignAccount => skipped.foreign_account += 1,
    }
}


fn malformed(error: serde_json::Error) -> ParseError {
    ParseError::Malformed {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}


/// Reads at most `max_bytes`, counts the findings of the root array before building any, then parses each one alone for the declared tenant and account.
pub fn parse_prowler_ocsf<Source: Read>(reader: Source, tenant: &str, account: &str, limits: &Limits) -> Result<Findings, ParseError> {
    let scope = tenant_scope(tenant).map_err(ParseError::Tenant)?;
    if !valid_reference(account, MAX_ACCOUNT_BYTES) {
        Err(ParseError::Account)?;
    }
    let max_bytes = limits.max_bytes.min(CEILING_MAX_BYTES);
    let mut buffer = Vec::new();
    let mut limited = reader.take(max_bytes.saturating_add(1));
    limited.read_to_end(&mut buffer).map_err(ParseError::Read)?;
    if limited.limit() == 0 {
        Err(ParseError::TooLarge { max: max_bytes })?;
    }
    let count = serde_json::from_slice::<Vec<IgnoredAny>>(&buffer).map_err(malformed)?.len();
    if count > limits.max_findings {
        Err(ParseError::TooManyFindings {
            count,
            max: limits.max_findings,
        })?;
    }
    let raws = serde_json::from_slice::<Vec<&RawValue>>(&buffer).map_err(malformed)?;
    let mut items = Vec::new();
    let mut skipped = Skipped::default();
    let mut seen = HashSet::new();
    for raw in &raws {
        match convert_finding(raw, account, limits) {
            Ok(finding) if seen.insert(identity_of(&finding)) => items.push(finding),
            Ok(_) => count_skip(&mut skipped, SkipReason::Duplicate),
            Err(reason) => count_skip(&mut skipped, reason),
        }
    }
    let kept = items.len();
    let refused = skipped.unparsable + skipped.bad_field + skipped.duplicate + skipped.foreign_account;
    if refused > 0 {
        tracing::warn!(kept, refused, "prowler findings refused");
    } else {
        tracing::info!(kept, "prowler findings parsed");
    }
    Ok(Findings {
        tenant: scope,
        account: account.to_owned(),
        items,
        skipped,
    })
}
