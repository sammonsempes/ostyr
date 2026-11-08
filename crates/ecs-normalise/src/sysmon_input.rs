use crate::error::SysmonError;
use crate::types::Fields;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde_json::{from_str, Value};
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
    pub system_time: Option<String>,
    pub fields: Fields,
}


#[derive(Debug, Default)]
enum Target {
    #[default]
    Nothing,
    EventId,
    Computer,
    Data(String),
}


#[derive(Debug, Default)]
struct Partial {
    target: Target,
    text: String,
    event_id: Option<String>,
    computer: Option<String>,
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


fn open(state: &mut Partial, start: &BytesStart<'_>) -> Result<(), SysmonError> {
    state.text.clear();
    state.target = match start.local_name().as_ref() {
        b"EventID" => Target::EventId,
        b"Computer" => Target::Computer,
        b"Data" => attribute(start, "Name")?.map_or(Target::Nothing, Target::Data),
        b"TimeCreated" => {
            state.system_time = attribute(start, "SystemTime")?;
            Target::Nothing
        }
        _ => Target::Nothing,
    };
    Ok(())
}


fn close(state: &mut Partial) -> Result<(), SysmonError> {
    let text = take(&mut state.text);
    match take(&mut state.target) {
        Target::EventId => state.event_id = Some(text),
        Target::Computer => state.computer = Some(text),
        Target::Data(name) => {
            state.fields.insert(name, text);
        }
        Target::Nothing => {}
    }
    Ok(())
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


fn json_state(text: &str) -> Result<Partial, SysmonError> {
    let value: Value = from_str(text).map_err(SysmonError::Json)?;
    let root = value.get("Event").unwrap_or(&value);
    let system = root.get("System").unwrap_or(root);
    let data = root
        .get("EventData")
        .and_then(Value::as_object)
        .ok_or(SysmonError::MissingField("EventData"))?;
    let fields = data
        .iter()
        .map(|(name, found)| {
            scalar(found)
                .map(|content| (name.clone(), content))
                .ok_or_else(|| SysmonError::BadValue(name.clone()))
        })
        .collect::<Result<Fields, SysmonError>>()?;
    Ok(Partial {
        event_id: system.get("EventID").and_then(scalar),
        computer: system.get("Computer").and_then(scalar),
        system_time: system.get("TimeCreated").and_then(|created| created.get("SystemTime")).and_then(scalar),
        fields,
        ..Partial::default()
    })
}


fn check_fields(fields: &Fields) -> Result<(), SysmonError> {
    if fields.len() > MAX_FIELDS {
        Err(SysmonError::TooManyFields { max: MAX_FIELDS })
    } else {
        fields.iter().try_for_each(|(name, value)| {
            if name.len() > MAX_FIELD_BYTES || value.len() > MAX_FIELD_BYTES {
                Err(SysmonError::FieldTooLong { max: MAX_FIELD_BYTES })
            } else {
                Ok(())
            }
        })
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
    check_fields(&state.fields)?;
    let id_text = state.event_id.ok_or(SysmonError::MissingField("EventID"))?;
    let event_id = id_text
        .trim()
        .parse()
        .map_err(|_| SysmonError::BadEventId(id_text.chars().take(MAX_ID_SHOWN).collect()))?;
    Ok(RawEvent {
        event_id,
        computer: state.computer,
        system_time: state.system_time,
        fields: state.fields,
    })
}
