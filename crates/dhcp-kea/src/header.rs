use crate::error::HeaderError;


pub const MAX_COLUMNS: usize = 64;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}


/// Column positions read from the header line of a lease file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Columns {
    pub family: Family,
    pub count: usize,
    pub address: usize,
    pub hwaddr: Option<usize>,
    pub duid: Option<usize>,
    pub expire: usize,
    pub valid_lifetime: usize,
    pub hostname: usize,
    pub state: usize,
    pub subnet_id: usize,
}


fn locate(names: &[&str], wanted: &'static str) -> Result<Option<usize>, HeaderError> {
    let positions: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, name)| **name == wanted)
        .map(|(index, _)| index)
        .collect();
    match positions.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(*index)),
        _ => Err(HeaderError::Duplicate(wanted)),
    }
}


fn required(names: &[&str], wanted: &'static str) -> Result<usize, HeaderError> {
    locate(names, wanted)?.ok_or(HeaderError::Missing(wanted))
}


/// Reads the column order from the header: unknown columns are ignored, a missing or repeated known column refuses the file.
pub fn parse_header(line: &str) -> Result<Columns, HeaderError> {
    let names: Vec<&str> = line.split(',').take(MAX_COLUMNS + 1).collect();
    if names.len() > MAX_COLUMNS {
        Err(HeaderError::TooManyColumns { max: MAX_COLUMNS })
    } else {
        let duid = locate(&names, "duid")?;
        let hwaddr = locate(&names, "hwaddr")?;
        let family = if duid.is_some() { Family::V6 } else { Family::V4 };
        if family == Family::V4 {
            required(&names, "hwaddr")?;
        }
        Ok(Columns {
            family,
            count: names.len(),
            address: required(&names, "address")?,
            hwaddr,
            duid,
            expire: required(&names, "expire")?,
            valid_lifetime: required(&names, "valid_lifetime")?,
            hostname: required(&names, "hostname")?,
            state: required(&names, "state")?,
            subnet_id: required(&names, "subnet_id")?,
        })
    }
}
