//! Pull parsing of a CycloneDX JSON document: nothing is built before it is counted.

use crate::error::SbomError;
use crate::limits::{COMPONENTS_KEY, MAX_JSON_NESTING, UNKNOWN_KIND};
use crate::model::{Component, Frame, FrameKind, Limits, Outcome, ParseState, Partial, Sbom};
use crate::purl::classify;
use std::io::Read;
use struson::reader::{JsonReader, JsonStreamReader, ReaderSettings, ValueType};


/// Reads at most `max_bytes` of the document, then at most `max_components` array elements, however long the input is.
pub fn parse_cyclonedx<Source: Read>(reader: Source, tenant: &str, artefact: &str, limits: &Limits) -> Result<Sbom, SbomError> {
    let mut limited = reader.take(u64::try_from(limits.max_bytes.saturating_add(1)).unwrap_or(u64::MAX));
    let parsed = parse_stream(&mut limited, tenant, artefact, limits);
    let oversized = limited.limit() == 0;
    match (oversized, parsed) {
        (true, _) => Err(SbomError::TooLarge { max: limits.max_bytes }),
        (false, result) => result,
    }
}


fn parse_stream<Source: Read>(source: Source, tenant: &str, artefact: &str, limits: &Limits) -> Result<Sbom, SbomError> {
    let settings = ReaderSettings {
        max_nesting_depth: Some(MAX_JSON_NESTING),
        ..ReaderSettings::default()
    };
    let mut reader = JsonStreamReader::new_custom(source, settings);
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
    reader.consume_trailing_whitespace()?;
    Ok(state.sbom)
}


fn frame(kind: FrameKind) -> Frame {
    Frame {
        kind,
        partial: Partial::default(),
    }
}


/// One token-level move; `None` once the document is closed. Every move consumes at least one byte.
pub fn step<Source: Read>(reader: &mut JsonStreamReader<Source>, state: &mut ParseState, limits: &Limits) -> Result<Option<()>, SbomError> {
    match state.stack.last().map(|top| top.kind) {
        None => Ok(None),
        Some(FrameKind::Root) => step_root(reader, state).map(Some),
        Some(FrameKind::Components) => step_components(reader, state, limits).map(Some),
        Some(FrameKind::Component) => step_component(reader, state, limits).map(Some),
    }
}


fn step_root<Source: Read>(reader: &mut JsonStreamReader<Source>, state: &mut ParseState) -> Result<(), SbomError> {
    if reader.has_next()? {
        let name = reader.next_name_owned()?;
        open_components(reader, state, &name)
    } else {
        reader.end_object()?;
        state.stack.pop();
        Ok(())
    }
}


fn open_components<Source: Read>(reader: &mut JsonStreamReader<Source>, state: &mut ParseState, name: &str) -> Result<(), SbomError> {
    if name == COMPONENTS_KEY && reader.peek()? == ValueType::Array {
        reader.begin_array()?;
        state.stack.push(frame(FrameKind::Components));
        Ok(())
    } else {
        Ok(reader.skip_value()?)
    }
}


fn step_components<Source: Read>(reader: &mut JsonStreamReader<Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
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


fn open_component<Source: Read>(reader: &mut JsonStreamReader<Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
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


fn step_component<Source: Read>(reader: &mut JsonStreamReader<Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
    if reader.has_next()? {
        let name = reader.next_name_owned()?;
        read_member(reader, state, limits, &name)
    } else {
        reader.end_object()?;
        state.stack.pop().into_iter().for_each(|closed| finish(&mut state.sbom, closed.partial));
        Ok(())
    }
}


fn read_member<Source: Read>(reader: &mut JsonStreamReader<Source>, state: &mut ParseState, limits: &Limits, name: &str) -> Result<(), SbomError> {
    match (name, reader.peek()?) {
        (COMPONENTS_KEY, ValueType::Array) => {
            reader.begin_array()?;
            state.stack.push(frame(FrameKind::Components));
            Ok(())
        }
        ("name" | "version" | "purl" | "type", ValueType::String) => {
            let text = reader.next_string()?;
            store(state, name, text, limits);
            Ok(())
        }
        _ => Ok(reader.skip_value()?),
    }
}


fn store(state: &mut ParseState, name: &str, mut text: String, limits: &Limits) {
    state.stack.iter_mut().rev().take(1).for_each(|open| {
        let oversize = text.len() > limits.max_string_bytes;
        open.partial.oversize |= oversize;
        let field = match name {
            "name" => &mut open.partial.name,
            "version" => &mut open.partial.version,
            "purl" => &mut open.partial.purl,
            _ => &mut open.partial.kind,
        };
        *field = (!oversize).then_some(std::mem::take(&mut text));
    });
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
