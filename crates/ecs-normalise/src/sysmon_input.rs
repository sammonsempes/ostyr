use crate::error::SysmonError;
use crate::types::Fields;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{from_str, Value};
use serde_with::{serde_as, MapPreventDuplicates};
use std::collections::BTreeMap;
use std::iter::from_fn;
use std::mem::take;


pub const MAX_EVENT_BYTES: usize = 65_536;


pub const MAX_FIELDS: usize = 128;


pub const MAX_FIELD_BYTES: usize = 8_192;


const MAX_ID_SHOWN: usize = 16;


/// One Sysmon event reduced to what the mapping reads, whatever its input format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    pub event_id: u32,
    pub computer: Option<String>,
    pub provider: Option<String>,
    pub channel: Option<String>,
    pub system_time: Option<String>,
    pub fields: Fields,
}


#[derive(Debug, Default)]
enum Target {
    #[default]
    Nothing,
    EventId,
    Computer,
    Channel,
    Data(String),
}


#[derive(Debug, Default)]
struct Partial {
    path: Vec<Vec<u8>>,
    roots: usize,
    target: Target,
    text: String,
    event_id: Option<String>,
    computer: Option<String>,
    provider: Option<String>,
    channel: Option<String>,
    system_time: Option<String>,
    fields: Fields,
}


fn attribute(start: &BytesStart<'_>, name: &str) -> Result<Option<String>, SysmonError> {
    start
        .attributes()
        .map(|found| found.map_err(quick_xml::Error::from))
        .try_fold(None, |value, found| {
            let attr = found?;
            if attr.key.local_name().as_ref() == name.as_bytes() {
                Ok(Some(attr.normalized_value(XmlVersion::Implicit1_0)?.into_owned()))
            } else {
                Ok(value)
            }
        })
}


fn set_once(slot: &mut Option<String>, value: Option<String>, name: &'static str) -> Result<(), SysmonError> {
    match (slot.is_some(), value) {
        (true, Some(_)) => Err(SysmonError::Duplicate(name)),
        (_, found) => {
            *slot = found.or_else(|| slot.take());
            Ok(())
        }
    }
}


fn check_roots(roots: usize) -> Result<(), SysmonError> {
    if roots > 1 {
        Err(SysmonError::MultipleRoots)
    } else {
        Ok(())
    }
}


fn open(state: &mut Partial, start: &BytesStart<'_>) -> Result<(), SysmonError> {
    state.text.clear();
    state.path.push(start.local_name().as_ref().to_vec());
    state.roots += usize::from(state.path.len() == 1);
    check_roots(state.roots)?;
    let names: Vec<&[u8]> = state.path.iter().map(Vec::as_slice).collect();
    let place = match names.as_slice() {
        [b"Event", b"System", b"EventID"] => Target::EventId,
        [b"Event", b"System", b"Computer"] => Target::Computer,
        [b"Event", b"System", b"Channel"] => Target::Channel,
        [b"Event", b"System", b"Provider"] => {
            let name = attribute(start, "Name")?;
            set_once(&mut state.provider, name, "Provider")?;
            Target::Nothing
        }
        [b"Event", b"System", b"TimeCreated"] => {
            let time = attribute(start, "SystemTime")?;
            set_once(&mut state.system_time, time, "TimeCreated")?;
            Target::Nothing
        }
        [b"Event", b"EventData", b"Data"] => attribute(start, "Name")?.map_or(Target::Nothing, Target::Data),
        _ => Target::Nothing,
    };
    state.target = place;
    Ok(())
}


fn close(state: &mut Partial) -> Result<(), SysmonError> {
    let text = take(&mut state.text);
    state.path.pop();
    match take(&mut state.target) {
        Target::EventId => set_once(&mut state.event_id, Some(text), "EventID"),
        Target::Computer => set_once(&mut state.computer, Some(text), "Computer"),
        Target::Channel => set_once(&mut state.channel, Some(text), "Channel"),
        Target::Data(name) => match state.fields.insert(name, text) {
            Some(_) => Err(SysmonError::Duplicate("Data")),
            None => Ok(()),
        },
        Target::Nothing => Ok(()),
    }
}


fn add_text(state: &mut Partial, piece: &str) -> Result<(), SysmonError> {
    state.text.push_str(piece);
    Ok(())
}


fn append_reference(state: &mut Partial, name: &str, character: Option<char>) -> Result<(), SysmonError> {
    match (character, resolve_predefined_entity(name)) {
        (Some(found), _) => add_text(state, &found.to_string()),
        (None, Some(entity)) => add_text(state, entity),
        (None, None) => Err(SysmonError::UnknownEntity(name.to_string())),
    }
}


fn step(state: &mut Partial, event: Event<'_>) -> Result<(), SysmonError> {
    match event {
        Event::Start(start) => open(state, &start),
        Event::Empty(start) => open(state, &start).and_then(|()| close(state)),
        Event::End(_) => close(state),
        Event::Text(text) => add_text(state, &text.decode()?),
        Event::CData(data) => add_text(state, &data.decode()?),
        Event::GeneralRef(reference) => append_reference(state, &reference.decode()?, reference.resolve_char_ref()?),
        _ => Ok(()),
    }
}


fn xml_state(text: &str) -> Result<Partial, SysmonError> {
    let mut reader = Reader::from_str(text);
    let mut state = Partial::default();
    from_fn(|| match reader.read_event() {
        Ok(Event::Eof) => None,
        other => Some(other),
    })
    .try_for_each(|event| step(&mut state, event?))?;
    Ok(state)
}


fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}


#[derive(Debug, Default, Deserialize)]
struct JsonProvider {
    #[serde(rename = "Name")]
    name: Option<Value>,
}


#[derive(Debug, Default, Deserialize)]
struct JsonCreated {
    #[serde(rename = "SystemTime")]
    system_time: Option<Value>,
}


#[derive(Debug, Default, Deserialize)]
struct JsonSystem {
    #[serde(rename = "EventID")]
    event_id: Option<Value>,
    #[serde(rename = "Computer")]
    computer: Option<Value>,
    #[serde(rename = "Provider")]
    provider: Option<Box<RawValue>>,
    #[serde(rename = "Channel")]
    channel: Option<Value>,
    #[serde(rename = "TimeCreated")]
    time_created: Option<JsonCreated>,
}


#[serde_as]
#[derive(Debug, Default, Deserialize)]
struct JsonBody {
    #[serde(rename = "System")]
    system: Option<JsonSystem>,
    #[serde(rename = "EventData")]
    #[serde_as(as = "Option<MapPreventDuplicates<_, _>>")]
    event_data: Option<BTreeMap<String, Value>>,
    #[serde(flatten)]
    flat: JsonSystem,
}


#[derive(Debug, Default, Deserialize)]
struct JsonEnvelope {
    #[serde(rename = "Event")]
    event: Option<JsonBody>,
}


fn json_error(error: serde_json::Error) -> SysmonError {
    if error.to_string().contains("duplicate") {
        SysmonError::DuplicateKey(error)
    } else {
        SysmonError::Json(error)
    }
}


fn json_provider(raw: &str) -> Result<Option<Value>, SysmonError> {
    if raw.trim_start().starts_with('{') {
        Ok(from_str::<JsonProvider>(raw).map_err(json_error)?.name)
    } else {
        Ok(Some(from_str(raw).map_err(json_error)?))
    }
}


fn json_state(text: &str) -> Result<Partial, SysmonError> {
    let envelope: JsonEnvelope = from_str(text).map_err(json_error)?;
    let body = envelope.event.map_or_else(|| from_str(text).map_err(json_error), Ok)?;
    let system = body.system.unwrap_or(body.flat);
    let data = body.event_data.ok_or(SysmonError::MissingField("EventData"))?;
    let fields = data
        .into_iter()
        .map(|(name, found)| scalar(&found).map(|content| (name.clone(), content)).ok_or(SysmonError::BadValue(name)))
        .collect::<Result<Fields, SysmonError>>()?;
    let provider = system.provider.map(|raw| json_provider(raw.get())).transpose()?.flatten();
    Ok(Partial {
        event_id: system.event_id.as_ref().and_then(scalar),
        computer: system.computer.as_ref().and_then(scalar),
        provider: provider.as_ref().and_then(scalar),
        channel: system.channel.as_ref().and_then(scalar),
        system_time: system.time_created.and_then(|created| created.system_time).as_ref().and_then(scalar),
        fields,
        ..Partial::default()
    })
}


fn cut_value(value: String) -> String {
    if value.len() > MAX_FIELD_BYTES {
        let end = (0..=MAX_FIELD_BYTES).rev().find(|at| value.is_char_boundary(*at)).unwrap_or(0);
        let omitted = value.len() - end;
        format!("{}[cut, {omitted} bytes]", value.split_at(end).0)
    } else {
        value
    }
}


fn bound_fields(fields: Fields) -> Result<Fields, SysmonError> {
    if fields.len() > MAX_FIELDS {
        Err(SysmonError::TooManyFields { max: MAX_FIELDS })
    } else {
        fields
            .into_iter()
            .map(|(name, value)| {
                if name.len() > MAX_FIELD_BYTES {
                    Err(SysmonError::FieldTooLong { max: MAX_FIELD_BYTES })
                } else {
                    Ok((name, cut_value(value)))
                }
            })
            .collect()
    }
}


fn partial(text: &str) -> Result<Partial, SysmonError> {
    if text.len() > MAX_EVENT_BYTES {
        Err(SysmonError::TooLong { max: MAX_EVENT_BYTES })
    } else if text.trim_start().starts_with('{') {
        json_state(text)
    } else {
        xml_state(text)
    }
}


/// Parses a rendered Sysmon event (XML, or JSON when the text starts with `{`) within the size, count and length caps.
pub fn parse_event(text: &str) -> Result<RawEvent, SysmonError> {
    let state = partial(text)?;
    let fields = bound_fields(state.fields)?;
    let id_text = state.event_id.ok_or(SysmonError::MissingField("EventID"))?;
    let event_id = id_text
        .trim()
        .parse()
        .map_err(|_| SysmonError::BadEventId(id_text.chars().take(MAX_ID_SHOWN).collect()))?;
    Ok(RawEvent {
        event_id,
        computer: state.computer,
        provider: state.provider,
        channel: state.channel,
        system_time: state.system_time,
        fields,
    })
}
