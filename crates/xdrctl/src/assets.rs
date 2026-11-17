use crate::alerts::{is_hidden, map_status, page_path, printable};
use crate::commands::{bad_reply, call_with_session, FIRST_SUCCESS};
use crate::error::CliError;
use crate::model::{AssetAttributeView, AssetDetailView, AssetKeyView, AssetPageView, AssetSummaryView, Context, HttpMethod, Report};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use unicode_bidi::bidi_class;


pub const ASSET_ID_MAX_BYTES: usize = 512;


/// Everything outside RFC 3986 unreserved characters is encoded, so an id is always one path segment.
pub const ID_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');


pub const DOT_SEGMENTS: [&str; 2] = [".", ".."];


pub const ENCODED_DOT: &str = "%2E";


/// The id grammar checked before any request: 1 to 512 bytes, no hidden character, no leading `-`.
pub fn valid_asset_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= ASSET_ID_MAX_BYTES && !id.starts_with('-') && !id.chars().any(is_hidden)
}


/// One path segment: `.` and `..` get their dots encoded too, so no client or proxy can resolve them.
pub fn id_segment(id: &str) -> String {
    if DOT_SEGMENTS.contains(&id) {
        id.replace('.', ENCODED_DOT)
    } else {
        utf8_percent_encode(id, ID_ENCODE_SET).to_string()
    }
}


pub const REORDERED_CLASSES: [&str; 3] = ["R", "AL", "AN"];


/// True for the bidi classes R, AL and AN, compared by their Unicode short names (`BidiClass` is a Debug-printed enum).
pub fn is_reordered(character: char) -> bool {
    REORDERED_CLASSES.contains(&format!("{:?}", bidi_class(character)).as_str())
}


/// `printable` plus an escape for every character of bidi class R, AL or AN, which terminals may reorder.
pub fn id_printable(id: &str) -> String {
    id.chars()
        .map(|character| {
            if is_reordered(character) {
                character.escape_unicode().to_string()
            } else {
                printable(&character.to_string())
            }
        })
        .collect()
}


pub fn table_row(asset: &AssetSummaryView) -> String {
    let counts = &asset.counts;
    [
        id_printable(&asset.id),
        printable(&asset.kind),
        printable(&asset.lifecycle),
        asset.version.to_string(),
        counts.keys.to_string(),
        counts.attributes.to_string(),
        counts.open_conflicts.to_string(),
    ]
    .join("\t")
}


pub fn list_text(page: &AssetPageView) -> String {
    let footer = page
        .next_cursor
        .as_deref()
        .map_or_else(|| "no more assets".to_owned(), |cursor| format!("next cursor: {}", printable(cursor)));
    std::iter::once("id\tkind\tlifecycle\tversion\tkeys\tattributes\topen conflicts".to_owned())
        .chain(page.items.iter().map(table_row))
        .chain(std::iter::once(footer))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn key_line(key: &AssetKeyView) -> String {
    format!("key: {} = {}", printable(&key.key), printable(&key.value))
}


pub fn attribute_line(attribute: &AssetAttributeView) -> String {
    format!(
        "attribute: {} = {} (source {})",
        printable(&attribute.name),
        printable(&attribute.value),
        printable(&attribute.source)
    )
}


pub fn truncated_line(asset: &AssetDetailView) -> Option<String> {
    asset.truncated.then(|| {
        let counts = &asset.summary.counts;
        format!(
            "truncated (showing {} of {} keys, {} of {} attributes)",
            asset.keys.len(),
            counts.keys,
            asset.attributes.len(),
            counts.attributes
        )
    })
}


pub fn show_text(asset: &AssetDetailView) -> String {
    let summary = &asset.summary;
    let counts = &summary.counts;
    [
        format!("id: {}", id_printable(&summary.id)),
        format!("kind: {}", printable(&summary.kind)),
        format!("lifecycle: {}", printable(&summary.lifecycle)),
        format!("version: {}", summary.version),
        format!(
            "counts: keys {} attributes {} open conflicts {}",
            counts.keys, counts.attributes, counts.open_conflicts
        ),
    ]
    .into_iter()
    .chain(asset.keys.iter().map(key_line))
    .chain(asset.attributes.iter().map(attribute_line))
    .chain(truncated_line(asset))
    .collect::<Vec<_>>()
    .join("\n")
}


pub fn assets_list(ctx: &Context, limit: Option<u32>, cursor: Option<&str>) -> Result<Report, CliError> {
    let path = page_path("/assets", limit, cursor)?;
    let body = call_with_session(ctx, HttpMethod::Get, &path).map_err(map_status)?;
    let page: AssetPageView = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
    Ok(Report {
        text: list_text(&page),
        json: serde_json::from_str(&body)?,
    })
}


pub fn assets_show(ctx: &Context, id: &str) -> Result<Report, CliError> {
    if valid_asset_id(id) {
        let body = call_with_session(ctx, HttpMethod::Get, &format!("/assets/{}", id_segment(id))).map_err(map_status)?;
        let asset: AssetDetailView = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
        Ok(Report {
            text: show_text(&asset),
            json: serde_json::from_str(&body)?,
        })
    } else {
        Err(CliError::InvalidArgument("asset id"))
    }
}
