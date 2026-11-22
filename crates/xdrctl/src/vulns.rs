use crate::alerts::{map_status, printable};
use crate::assets::{id_printable, id_segment, valid_asset_id, ID_ENCODE_SET};
use crate::commands::{bad_reply, call_with_session, FIRST_SUCCESS};
use crate::error::CliError;
use crate::model::{Context, FindingView, FindingsAssetReply, FindingsListReply, HttpMethod, Report};
use percent_encoding::utf8_percent_encode;


pub const CURSOR_SEPARATOR: char = ' ';


pub const CURSOR_FIELDS: usize = 5;


pub const PRIORITY_MAX_DIGITS: usize = 10;


pub const FIELD_MAX_BYTES: usize = 128;


pub const CVSS_PRECISION: usize = 1;


pub const EPSS_PRECISION: usize = 4;


pub const NONE_MARK: &str = "-";


pub const TABLE_HEADER: &str = "asset\tecosystem\tpackage\trecord\tinstalled\tfixed\tcvss\tepss\tkev\tpriority\tfirst seen\tlast seen";


/// The server's stored-text grammar (`is_field`): 1 to 128 printable ASCII bytes without space, no leading `-`.
pub fn valid_field(text: &str) -> bool {
    (1..=FIELD_MAX_BYTES).contains(&text.len()) && !text.starts_with('-') && text.chars().all(|found| found.is_ascii_graphic())
}


/// The cursor the store builds (`cursor_of`): a priority and four fields joined by single spaces; a pre-filter, the server stays the authority.
pub fn valid_vuln_cursor(cursor: &str) -> bool {
    let parts: Vec<&str> = cursor.split(CURSOR_SEPARATOR).collect();
    let priority_fits = parts
        .first()
        .is_some_and(|text| text.len() <= PRIORITY_MAX_DIGITS && text.parse::<u32>().is_ok_and(|parsed| parsed.to_string() == *text));
    parts.len() == CURSOR_FIELDS && priority_fits && parts.iter().skip(1).all(|text| valid_field(text))
}


/// The path with the cursor percent-encoded (space, `&`, `%`, `+` and every other reserved byte), so it is one parameter value.
pub fn list_path(limit: Option<u32>, cursor: Option<&str>) -> Result<String, CliError> {
    if cursor.is_some_and(|value| !valid_vuln_cursor(value)) {
        Err(CliError::InvalidArgument("cursor"))
    } else {
        let query = limit
            .map(|value| format!("limit={value}"))
            .into_iter()
            .chain(cursor.map(|value| format!("cursor={}", utf8_percent_encode(value, ID_ENCODE_SET))))
            .collect::<Vec<_>>()
            .join("&");
        Ok(if query.is_empty() {
            "/vulnerabilities/findings".to_owned()
        } else {
            format!("/vulnerabilities/findings?{query}")
        })
    }
}


/// A fixed precision; a non-finite value is `-`.
pub fn fixed(value: f64, precision: usize) -> String {
    if value.is_finite() {
        format!("{value:.precision$}")
    } else {
        NONE_MARK.to_owned()
    }
}


pub fn finding_row(finding: &FindingView) -> String {
    [
        id_printable(&finding.asset),
        printable(&finding.ecosystem),
        printable(&finding.package),
        printable(&finding.record_id),
        printable(&finding.installed_version),
        finding.fixed_version.as_deref().map_or_else(|| NONE_MARK.to_owned(), printable),
        fixed(finding.cvss, CVSS_PRECISION),
        fixed(finding.epss, EPSS_PRECISION),
        finding.kev.to_string(),
        finding.priority.to_string(),
        printable(&finding.first_seen),
        printable(&finding.last_seen),
    ]
    .join("\t")
}


pub fn skipped_line(skipped: usize) -> Option<String> {
    (skipped > 0).then(|| format!("skipped: {skipped} stored findings outside the grammar"))
}


/// A cursor of the store's grammar is ASCII without control characters and printed as is, so `--cursor` takes it back verbatim.
pub fn cursor_text(cursor: &str) -> String {
    if valid_vuln_cursor(cursor) {
        cursor.to_owned()
    } else {
        printable(cursor)
    }
}


pub fn list_text(reply: &FindingsListReply) -> String {
    let footer = reply
        .next_cursor
        .as_deref()
        .map_or_else(|| "no more findings".to_owned(), |cursor| format!("next cursor: {}", cursor_text(cursor)));
    std::iter::once(TABLE_HEADER.to_owned())
        .chain(reply.items.iter().map(finding_row))
        .chain(skipped_line(reply.skipped))
        .chain(std::iter::once(footer))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn asset_text(reply: &FindingsAssetReply) -> String {
    std::iter::once(TABLE_HEADER.to_owned())
        .chain(reply.items.iter().map(finding_row))
        .chain(skipped_line(reply.skipped))
        .chain(reply.truncated.then(|| "TRUNCATED: the server cut this asset's findings".to_owned()))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn vulns_list(ctx: &Context, limit: Option<u32>, cursor: Option<&str>) -> Result<Report, CliError> {
    let path = list_path(limit, cursor)?;
    let body = call_with_session(ctx, HttpMethod::Get, &path).map_err(map_status)?;
    let reply: FindingsListReply = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
    Ok(Report {
        text: list_text(&reply),
        json: serde_json::from_str(&body)?,
    })
}


pub fn vulns_show(ctx: &Context, asset: &str) -> Result<Report, CliError> {
    if valid_asset_id(asset) {
        let path = format!("/vulnerabilities/assets/{}", id_segment(asset));
        let body = call_with_session(ctx, HttpMethod::Get, &path).map_err(map_status)?;
        let reply: FindingsAssetReply = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
        Ok(Report {
            text: asset_text(&reply),
            json: serde_json::from_str(&body)?,
        })
    } else {
        Err(CliError::InvalidArgument("asset id"))
    }
}
