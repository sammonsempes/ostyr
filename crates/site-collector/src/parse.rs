use crate::error::ParseError;
use crate::model::{SdElement, SyslogRecord, FACILITY_WEIGHT, MAX_APP_BYTES, MAX_HOST_BYTES, MAX_SD_ELEMENTS, MAX_SD_PARAMS, MAX_SD_STRING_BYTES};
use chrono::Utc;
use syslog_loose::{parse_message_with_year_exact_tz, Message, StructuredElement, Variant};


fn within(len: usize, max: usize, error: ParseError) -> Result<(), ParseError> {
    (len <= max).then_some(()).ok_or(error)
}


fn bounded_field(value: Option<&str>, max: usize, field: &'static str) -> Result<Option<String>, ParseError> {
    value
        .map(|text| within(text.len(), max, ParseError::FieldTooLong(field)).map(|()| text.to_string()))
        .transpose()
}


fn bounded_text(text: &str) -> Result<String, ParseError> {
    within(text.len(), MAX_SD_STRING_BYTES, ParseError::TooMuchStructuredData).map(|()| text.to_string())
}


fn bound_element(element: &StructuredElement<&str>) -> Result<SdElement, ParseError> {
    within(element.params.len(), MAX_SD_PARAMS, ParseError::TooMuchStructuredData)?;
    let params = element
        .params()
        .map(|(name, value)| Ok((bounded_text(name)?, bounded_text(&value)?)))
        .collect::<Result<Vec<_>, ParseError>>()?;
    Ok(SdElement {
        id: bounded_text(element.id)?,
        params,
    })
}


fn bound_structured_data(elements: &[StructuredElement<&str>]) -> Result<Vec<SdElement>, ParseError> {
    within(elements.len(), MAX_SD_ELEMENTS, ParseError::TooMuchStructuredData)?;
    elements.iter().map(bound_element).collect()
}


fn bound(message: &Message<&str>) -> Result<SyslogRecord, ParseError> {
    let priority = message
        .facility
        .zip(message.severity)
        .map(|(facility, severity)| facility as u8 * FACILITY_WEIGHT + severity as u8)
        .ok_or(ParseError::MissingPriority)?;
    Ok(SyslogRecord {
        priority,
        timestamp: message.timestamp.map(|timestamp| timestamp.timestamp()),
        host: bounded_field(message.hostname, MAX_HOST_BYTES, "hostname")?,
        app: bounded_field(message.appname, MAX_APP_BYTES, "app")?,
        message: message.msg.to_string(),
        structured_data: bound_structured_data(&message.structured_data)?,
    })
}


pub fn parse_syslog(payload: &[u8], year: i32) -> Result<SyslogRecord, ParseError> {
    let text = std::str::from_utf8(payload)?;
    let message = parse_message_with_year_exact_tz(text, move |_| year, Some(Utc), Variant::Either).map_err(|_| ParseError::Malformed)?;
    bound(&message)
}
