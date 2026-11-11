//! SPDX 2.x JSON packages: the same pull parser, caps and `finish` path as CycloneDX.

use crate::error::SbomError;
use crate::limits::MAX_EXTERNAL_REFS;
use crate::model::{Format, FrameKind, Limits, ParseState, Partial, Sbom};
use crate::parse::{finish, frame, parse_format, read_name, read_text};
use crate::types::Reader;
use std::io::Read;
use struson::reader::{JsonReader, ValueType};


const PURL_TYPE: &str = "purl";


/// Reads the top-level `packages` array under the caps of `parse_cyclonedx`; every other member is skipped unread.
pub fn parse_spdx<Source: Read>(source: Source, tenant: &str, artefact: &str, limits: &Limits) -> Result<Sbom, SbomError> {
    parse_format(source, tenant, artefact, limits, Format::Spdx)
}


pub fn step_package<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
    if reader.has_next()? {
        let name = read_name(reader, limits)?;
        read_package_member(reader, state, limits, &name)
    } else {
        reader.end_object()?;
        state.stack.pop().into_iter().for_each(|closed| finish(&mut state.sbom, closed.partial));
        Ok(())
    }
}


fn read_package_member<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits, name: &str) -> Result<(), SbomError> {
    match (name, reader.peek()?) {
        ("externalRefs", ValueType::Array) => {
            reader.begin_array()?;
            state.stack.push(frame(FrameKind::Refs));
            Ok(())
        }
        ("name" | "versionInfo" | "primaryPackagePurpose", ValueType::String) => {
            let text = read_text(reader, limits)?;
            store_package(state, name, text);
            Ok(())
        }
        _ => Ok(reader.skip_value()?),
    }
}


fn store_package(state: &mut ParseState, name: &str, mut text: Option<String>) {
    state.stack.iter_mut().rev().take(1).for_each(|open| {
        open.partial.oversize |= text.is_none();
        match name {
            "name" => open.partial.name = text.take(),
            "versionInfo" => open.partial.version = text.take(),
            _ => open.partial.kind = text.take().map(|purpose| purpose.to_lowercase()),
        }
    });
}


pub fn step_refs<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState) -> Result<(), SbomError> {
    if reader.has_next()? {
        state.stack.iter_mut().rev().take(1).for_each(|open| open.partial.refs += 1);
        let count = state.stack.last().map_or(0, |open| open.partial.refs);
        open_ref(reader, state, count)
    } else {
        reader.end_array()?;
        state.stack.pop();
        Ok(())
    }
}


fn open_ref<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, count: usize) -> Result<(), SbomError> {
    match (count <= MAX_EXTERNAL_REFS, reader.peek()?) {
        (true, ValueType::Object) => {
            reader.begin_object()?;
            state.stack.push(frame(FrameKind::Ref));
            Ok(())
        }
        (true, _) => Ok(reader.skip_value()?),
        (false, _) => {
            state
                .stack
                .iter_mut()
                .rev()
                .nth(1)
                .into_iter()
                .for_each(|package| package.partial.oversize = true);
            Ok(reader.skip_value()?)
        }
    }
}


pub fn step_ref<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits) -> Result<(), SbomError> {
    if reader.has_next()? {
        let name = read_name(reader, limits)?;
        read_ref_member(reader, state, limits, &name)
    } else {
        reader.end_object()?;
        state.stack.pop().into_iter().for_each(|closed| merge_ref(state, closed.partial));
        Ok(())
    }
}


fn read_ref_member<Source: Read>(reader: &mut Reader<'_, Source>, state: &mut ParseState, limits: &Limits, name: &str) -> Result<(), SbomError> {
    match (name, reader.peek()?) {
        ("referenceType" | "referenceCategory" | "referenceLocator", ValueType::String) => {
            let text = read_text(reader, limits)?;
            store_ref(state, name, text);
            Ok(())
        }
        _ => Ok(reader.skip_value()?),
    }
}


fn store_ref(state: &mut ParseState, name: &str, mut text: Option<String>) {
    state.stack.iter_mut().rev().take(1).for_each(|open| {
        open.partial.oversize |= text.is_none();
        match name {
            "referenceType" => open.partial.ref_type = text.take(),
            "referenceCategory" => open.partial.ref_category = text.take(),
            _ => open.partial.purl = text.take(),
        }
    });
}


/// The first package-manager purl reference is the component's purl; later ones are counted. An over-long purl skips the package.
fn merge_ref(state: &mut ParseState, mut closed: Partial) {
    let is_purl =
        closed.ref_type.as_deref() == Some(PURL_TYPE) && matches!(closed.ref_category.as_deref(), Some("PACKAGE-MANAGER" | "PACKAGE_MANAGER"));
    state.stack.iter_mut().rev().nth(1).into_iter().filter(|_| is_purl).for_each(|package| {
        package.partial.oversize |= closed.oversize;
        let taken = package.partial.purl.is_some();
        package.partial.extra_purls += usize::from(taken);
        package.partial.purl = package.partial.purl.take().or(closed.purl.take());
    });
}
