//! Pull parsing of a CycloneDX JSON document: nothing is built before it is counted.

use crate::error::SbomError;
use crate::limits::{COMPONENTS_KEY, MAX_JSON_NESTING, NAME_QUOTES, UNKNOWN_KIND};
use crate::model::{Component, Frame, FrameKind, Limits, Outcome, ParseState, Partial, Sbom};
use crate::purl::classify;
use crate::types::Reader;
use std::io::Read;
use struson::reader::{JsonReader, JsonStreamReader, ReaderSettings, ValueType};


/// Reads at most `max_bytes` of the document, then at most `max_components` array elements, however long the input is.
pub fn parse_cyclonedx<Source: Read>(source: Source, tenant: &str, artefact: &str, limits: &Limits) -> Result<Sbom, SbomError> {
    let settings = ReaderSettings {
        max_nesting_depth: Some(MAX_JSON_NESTING),
        track_path: false,
        ..ReaderSettings::default()
    };
    let mut limited = source.take(to_u64(limits.max_bytes.saturating_add(1)));
    let parsed = parse_stream(JsonStreamReader::new_custom(&mut limited, settings), tenant, artefact, limits);
    let oversized = limited.limit() == 0;
    match (oversized, parsed) {
        (true, _) => Err(SbomError::TooLarge { max: limits.max_bytes }),
        (false, result) => result,
    }
}


pub fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}


fn parse_stream<Source: Read>(mut reader: Reader<'_, Source>, tenant: &str, artefact: &str, limits: &Limits) -> Result<Sbom, SbomError> {
    reader.begin_object()?;
    let mut state = ParseState {
        stack: vec![frame(FrameKind::Root)],
        sbom: Sbom {
            tenant: tenant.to_string(),
            artefact: artefact.to_string(),
            components: Vec::new(),
            skipped: 0,
            bad_purls: 0,
            unmapped: 0,
        },
        seen: 0,
    };
    std::iter::repeat_with(|| step(&mut reader, &mut state, limits))
        .take(limits.max_bytes)
        .take_while(|outcome| !matches!(outcome, Ok(None)))
        .try_for_each(|outcome| outcome.map(|_| ()))?;
    match state.stack.is_empty() {
        true => {
            reader.consume_trailing_whitespace()?;
            Ok(state.sbom)
        }
        false => Err(SbomError::TooLarge { max: limits.max_bytes }),
    }
}


fn frame(kind: FrameKind) -> Frame {
    Frame {
        kind,
        partial: Partial::default(),
    }
}


/// One token-level move; `None` once the document is closed. Every move consumes at least one byte.
pub fn step<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits) -> Result<Option<()>, SbomError> {
    match state.stack.last().map(|top| top.kind) {
        None => Ok(None),
        Some(FrameKind::Root) => step_root(reader, state, limits).map(Some),
        Some(FrameKind::Components) => step_components(reader, state, limits).map(Some),
        Some(FrameKind::Component) => step_component(reader, state, limits).map(Some),
    }
}


fn step_root<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
    if reader.has_next()? {
        let name = read_name(reader, limits)?;
        open_components(reader, state, &name)
    } else {
        reader.end_object()?;
        state.stack.pop();
        Ok(())
    }
}


fn open_components<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, name: &str) -> Result<(), SbomError> {
    if name == COMPONENTS_KEY && reader.peek()? == ValueType::Array {
        reader.begin_array()?;
        state.stack.push(frame(FrameKind::Components));
        Ok(())
    } else {
        Ok(reader.skip_value()?)
    }
}


fn step_components<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
    if reader.has_next()? {
        state.seen += 1;
        (state.seen <= limits.max_components)
            .then_some(())
            .ok_or(SbomError::TooMany { max: limits.max_components })?;
        open_component(reader, state, limits)
    } else {
        reader.end_array()?;
        state.stack.pop();
        Ok(())
    }
}


fn open_component<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
    if reader.peek()? == ValueType::Object {
        let depth = state.stack.iter().filter(|open| open.kind == FrameKind::Component).count() + 1;
        (depth <= limits.max_depth)
            .then_some(())
            .ok_or(SbomError::TooDeep { max: limits.max_depth })?;
        reader.begin_object()?;
        state.stack.push(frame(FrameKind::Component));
        Ok(())
    } else {
        reader.skip_value()?;
        state.sbom.skipped += 1;
        Ok(())
    }
}


fn step_component<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
    if reader.has_next()? {
        let name = read_name(reader, limits)?;
        read_member(reader, state, limits, &name)
    } else {
        reader.end_object()?;
        state.stack.pop().into_iter().for_each(|closed| finish(&mut state.sbom, closed.partial));
        Ok(())
    }
}


fn read_member<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits, name: &str) -> Result<(), SbomError> {
    match (name, reader.peek()?) {
        (COMPONENTS_KEY, ValueType::Array) => {
            reader.begin_array()?;
            state.stack.push(frame(FrameKind::Components));
            Ok(())
        }
        ("name" | "version" | "purl" | "type", ValueType::String) => {
            let text = read_text(reader, limits)?;
            store(state, name, text);
            Ok(())
        }
        _ => Ok(reader.skip_value()?),
    }
}


fn store(state: &mut ParseState, name: &str, mut text: Option<String>) {
    state.stack.iter_mut().rev().take(1).for_each(|open| {
        open.partial.oversize |= text.is_none();
        let field = match name {
            "name" => &mut open.partial.name,
            "version" => &mut open.partial.version,
            "purl" => &mut open.partial.purl,
            _ => &mut open.partial.kind,
        };
        *field = text.take();
    });
}


/// A member name is read under a source limit of `max_string_bytes` plus its quotes: a longer one ends the parse.
fn read_name<Source: Read>(reader: &mut Reader<'_, Source>, limits: &Limits) -> Result<String, SbomError> {
    let remaining = reader.reader_mut().limit();
    let allowed = remaining.min(to_u64(limits.max_string_bytes.saturating_add(NAME_QUOTES)));
    reader.reader_mut().set_limit(allowed);
    let name = reader.next_name_owned();
    let left = remaining.saturating_sub(allowed.saturating_sub(reader.reader_mut().limit()));
    let cut = allowed < remaining && reader.reader_mut().limit() == 0;
    reader.reader_mut().set_limit(left);
    match (name, cut) {
        (Ok(text), _) => Ok(text),
        (Err(_), true) => Err(SbomError::NameTooLong {
            max: limits.max_string_bytes,
        }),
        (Err(error), false) => Err(error.into()),
    }
}


/// A string value is streamed through a cap of `max_string_bytes` and the rest is drained unread: `None` when it is longer.
fn read_text<Source: Read>(reader: &mut Reader<'_, Source>, limits: &Limits) -> Result<Option<String>, SbomError> {
    let mut value = reader.next_string_reader()?;
    let mut bytes = Vec::new();
    value
        .by_ref()
        .take(to_u64(limits.max_string_bytes.saturating_add(1)))
        .read_to_end(&mut bytes)?;
    std::io::copy(&mut value, &mut std::io::sink())?;
    Ok((bytes.len() <= limits.max_string_bytes).then(|| String::from_utf8_lossy(&bytes).into_owned()))
}


/// A component without a usable name, or with an over-long string, is counted and skipped.
fn finish(sbom: &mut Sbom, partial: Partial) {
    let Partial {
        name: maybe_name,
        version,
        purl,
        kind,
        oversize,
    } = partial;
    match maybe_name.filter(|_| !oversize) {
        None => sbom.skipped += 1,
        Some(component_name) => {
            let classified = classify(purl.as_deref(), &component_name, version.as_deref());
            sbom.bad_purls += usize::from(classified.outcome == Outcome::Malformed);
            sbom.unmapped += usize::from(matches!(classified.outcome, Outcome::NoPurl | Outcome::Unmapped));
            sbom.components.push(Component {
                name: component_name,
                version,
                kind: kind.unwrap_or_else(|| UNKNOWN_KIND.to_string()),
                purl,
                key: classified.key,
                package: classified.package,
            });
        }
    }
}
