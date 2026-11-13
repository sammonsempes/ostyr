use crate::error::CostError;
use crate::load::MAX_TOTAL_ACCOUNTS;
use crate::model::{
    Columns, CostTable, Limits, OtherBucket, Row, SkipReason, State, DIMENSION_ACCOUNT_SERVICE, DIMENSION_OTHER, DIMENSION_TAG, DIMENSION_TAG_OTHER,
    DIMENSION_TOTAL,
};
use crate::types::{DayRange, SkipCounts, StoredKey};
use core_pg::scope::{tenant_scope, TenantScope};
use csv::{ErrorKind, Reader, ReaderBuilder, StringRecord};
use metrics_ingest::decode::is_forbidden;
use rust_decimal::Decimal;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};


/// Julian day of 1970-01-01, the first day of ClickHouse's `Date`.
pub const EPOCH_JULIAN_DAY: i32 = 2_440_588;


/// Days from 1970-01-01 to 2149-06-06, the last day of ClickHouse's `Date` (a `u16`).
pub const DATE_LAST_OFFSET: i32 = 65_535;


pub const COLUMN_AMOUNT: &str = "BilledCost";


pub const COLUMN_CURRENCY: &str = "BillingCurrency";


pub const COLUMN_ACCOUNT: &str = "BillingAccountId";


pub const COLUMN_START: &str = "ChargePeriodStart";


pub const COLUMN_SERVICE: &str = "ServiceName";


pub const COLUMN_TAGS: &str = "Tags";


pub const COLUMN_SUB_ACCOUNT: &str = "SubAccountId";


pub fn has_forbidden(text: &str) -> bool {
    text.chars().any(is_forbidden)
}


/// Plain decimal text only: digits, one optional sign and point; an exponent is refused.
pub fn parse_amount(text: &str) -> Option<Decimal> {
    let plain = !text.is_empty() && text.chars().all(|character| character.is_ascii_digit() || matches!(character, '.' | '-'));
    match (plain, Decimal::from_str(text)) {
        (true, Ok(amount)) => Some(amount),
        _ => None,
    }
}


pub fn add_cost(slot: &mut Decimal, amount: Decimal) -> Result<(), CostError> {
    let total = slot.checked_add(amount).ok_or(CostError::Overflow)?;
    *slot = total;
    Ok(())
}


pub fn column_index(header: &StringRecord, name: &str) -> Option<usize> {
    header.iter().position(|field| field == name)
}


pub fn required_column(header: &StringRecord, name: &'static str) -> Result<usize, CostError> {
    column_index(header, name).ok_or(CostError::MissingColumn { column: name })
}


pub fn locate_columns(header: &StringRecord) -> Result<Columns, CostError> {
    Ok(Columns {
        amount: required_column(header, COLUMN_AMOUNT)?,
        currency: required_column(header, COLUMN_CURRENCY)?,
        account: required_column(header, COLUMN_ACCOUNT)?,
        start: required_column(header, COLUMN_START)?,
        service: required_column(header, COLUMN_SERVICE)?,
        tags: column_index(header, COLUMN_TAGS),
        sub_account: column_index(header, COLUMN_SUB_ACCOUNT),
    })
}


pub fn field(record: &StringRecord, index: usize) -> &str {
    record.get(index).unwrap_or("")
}


pub fn is_label(text: &str) -> bool {
    !text.is_empty() && !has_forbidden(text)
}


pub fn parse_day(text: &str) -> Result<time::Date, SkipReason> {
    OffsetDateTime::parse(text, &Rfc3339)
        .map(|moment| moment.to_offset(UtcOffset::UTC).date())
        .map_err(|_| SkipReason::BadDate)
}


pub fn parse_tags(text: &str, limits: &Limits) -> Result<Vec<(String, String)>, SkipReason> {
    let parsed = match text.trim().is_empty() {
        true => Ok(BTreeMap::new()),
        false => serde_json::from_str::<BTreeMap<String, String>>(text),
    };
    let pairs = parsed.map_err(|_| SkipReason::BadTags)?;
    let valid = pairs.len() <= limits.max_tags_per_row && pairs.iter().all(|(key, value)| is_label(key) && !has_forbidden(value));
    if valid {
        Ok(pairs.into_iter().collect())
    } else {
        Err(SkipReason::BadTags)
    }
}


pub fn account_of(record: &StringRecord, columns: &Columns) -> String {
    let sub_account = columns.sub_account.map_or("", |index| field(record, index));
    if sub_account.is_empty() {
        field(record, columns.account).to_string()
    } else {
        sub_account.to_string()
    }
}


pub fn build_row(record: &StringRecord, columns: &Columns, limits: &Limits) -> Result<Row, SkipReason> {
    let account = account_of(record, columns);
    let service = field(record, columns.service);
    let currency = field(record, columns.currency);
    let labels_valid = is_label(&account) && is_label(service) && is_label(currency);
    if labels_valid {
        let amount = parse_amount(field(record, columns.amount)).ok_or(SkipReason::BadAmount)?;
        let day = parse_day(field(record, columns.start))?;
        let tags = match columns.tags {
            Some(index) => parse_tags(field(record, index), limits)?,
            None => Vec::new(),
        };
        Ok(Row {
            day,
            account,
            service: service.to_string(),
            currency: currency.to_string(),
            amount,
            tags,
        })
    } else {
        Err(SkipReason::Malformed)
    }
}


pub fn parse_row(record: &StringRecord, columns: &Columns, limits: &Limits) -> Result<Row, SkipReason> {
    if record.iter().any(|text| text.len() > limits.max_field_bytes) {
        Err(SkipReason::Oversized)
    } else {
        build_row(record, columns, limits)
    }
}


pub fn count_skip(skipped: &mut SkipCounts, reason: SkipReason) {
    *skipped.entry(reason).or_insert(0) += 1;
}


pub fn admits<Item: Ord>(seen: &BTreeSet<Item>, item: &Item, max_series: usize) -> bool {
    seen.contains(item) || seen.len() < max_series
}


pub fn add_other(bucket: &mut OtherBucket, amount: Decimal) -> Result<(), CostError> {
    bucket.count += 1;
    add_cost(&mut bucket.cost, amount)
}


/// Adds an amount to the per-account row of one dimension.
pub fn add_stored(table: &mut CostTable, key: StoredKey, amount: Decimal) -> Result<(), CostError> {
    add_cost(table.account_rows.entry(key).or_insert(Decimal::ZERO), amount)
}


pub fn post_tag(
    state: &mut State,
    (row_day, label): (time::Date, &str),
    pair: (String, String),
    amount: Decimal,
    limits: &Limits,
) -> Result<(), CostError> {
    if admits(&state.pairs, &pair, limits.max_series) {
        state.pairs.insert(pair.clone());
        let (key, value) = pair;
        add_stored(
            &mut state.table,
            (row_day, label.to_owned(), DIMENSION_TAG, key.clone(), value.clone()),
            amount,
        )?;
        add_cost(state.table.by_tag.entry((row_day, key, value)).or_insert(Decimal::ZERO), amount)
    } else {
        add_stored(
            &mut state.table,
            (row_day, label.to_owned(), DIMENSION_TAG_OTHER, String::new(), String::new()),
            amount,
        )?;
        add_other(&mut state.table.tag_other, amount)
    }
}


/// The account's own name always; the flag tells whether it is within `max_series` for the evaluation maps.
pub fn account_label(state: &mut State, account: &str, limits: &Limits) -> (bool, String) {
    let owned = account.to_owned();
    let within = admits(&state.accounts, &owned, limits.max_series);
    if within {
        state.accounts.insert(owned.clone());
    }
    (within, owned)
}


pub fn post_row(state: &mut State, row: Row, limits: &Limits) -> Result<(), CostError> {
    let Row {
        day,
        account,
        service,
        amount,
        tags,
        ..
    } = row;
    state.table.accepted += 1;
    add_cost(state.table.day_totals.entry(day).or_insert(Decimal::ZERO), amount)?;
    let (within, label) = account_label(state, &account, limits);
    add_stored(
        &mut state.table,
        (day, label.clone(), DIMENSION_TOTAL, String::new(), String::new()),
        amount,
    )?;
    let tracked = within && admits(&state.services, &service, limits.max_series);
    if tracked {
        state.services.insert(service.clone());
        add_stored(
            &mut state.table,
            (day, label.clone(), DIMENSION_ACCOUNT_SERVICE, service.clone(), String::new()),
            amount,
        )?;
        add_cost(
            state.table.by_account_service.entry((day, account, service)).or_insert(Decimal::ZERO),
            amount,
        )?;
    } else {
        add_stored(
            &mut state.table,
            (day, label.clone(), DIMENSION_OTHER, String::new(), String::new()),
            amount,
        )?;
        add_other(&mut state.table.other, amount)?;
    }
    let tag_scope = (day, label.as_str());
    tags.into_iter().try_for_each(|pair| post_tag(state, tag_scope, pair, amount, limits))
}


pub fn admit_row(state: &mut State, row: Row, limits: &Limits) -> Result<(), CostError> {
    let same_currency = state.table.currency.as_ref().is_none_or(|currency| *currency == row.currency);
    if same_currency {
        state.table.currency = Some(row.currency.clone());
        post_row(state, row, limits)
    } else {
        count_skip(&mut state.table.skipped, SkipReason::MixedCurrency);
        Ok(())
    }
}


pub fn apply_row(state: &mut State, parsed: Result<Row, SkipReason>, limits: &Limits) -> Result<(), CostError> {
    match parsed {
        Ok(row) => admit_row(state, row, limits),
        Err(reason) => {
            count_skip(&mut state.table.skipped, reason);
            Ok(())
        }
    }
}


/// The earliest and latest day of a range once `day` is added.
pub fn widen(range: Option<DayRange>, day: time::Date) -> DayRange {
    range.map_or((day, day), |(first, last)| (first.min(day), last.max(day)))
}


/// True when ClickHouse's `Date` holds the day (1970-01-01 to 2149-06-06); it saturates a parameter outside it.
pub fn in_date_range(day: time::Date) -> bool {
    (0..=DATE_LAST_OFFSET).contains(&(day.to_julian_day() - EPOCH_JULIAN_DAY))
}


/// A readable day inside the `Date` range widens the replace range; one outside it is only counted, so no row can widen the delete to all history.
pub fn note_day(table: &mut CostTable, parsed: Result<time::Date, SkipReason>) {
    match parsed {
        Ok(day) if in_date_range(day) => table.seen_days = Some(widen(table.seen_days, day)),
        Ok(_) => table.days_out_of_range += 1,
        Err(_) => {}
    }
}


/// Every row with a valid account label names its account and its day for the replace, skipped or not; the set stops growing past the total cap.
pub fn note_account(state: &mut State, record: &StringRecord, columns: &Columns, limits: &Limits) {
    let account = account_of(record, columns);
    if is_label(&account) && account.len() <= limits.max_field_bytes {
        if admits(&state.table.seen_accounts, &account, MAX_TOTAL_ACCOUNTS + 1) {
            state.table.seen_accounts.insert(account);
        }
        note_day(&mut state.table, parse_day(field(record, columns.start)));
    }
}


pub fn classify(state: &mut State, result: Result<StringRecord, csv::Error>, columns: &Columns, limits: &Limits) -> Result<(), CostError> {
    match result {
        Ok(record) => {
            note_account(state, &record, columns, limits);
            apply_row(state, parse_row(&record, columns, limits), limits)
        }
        Err(error) if matches!(error.kind(), ErrorKind::Io(_)) => Err(CostError::Read(error)),
        Err(_) => {
            count_skip(&mut state.table.skipped, SkipReason::Malformed);
            Ok(())
        }
    }
}


pub fn absorb(state: &mut State, result: Result<StringRecord, csv::Error>, columns: &Columns, limits: &Limits) -> Result<(), CostError> {
    state.rows += 1;
    if state.rows > limits.max_rows {
        Err(CostError::TooManyRows { limit: limits.max_rows })
    } else {
        classify(state, result, columns, limits)
    }
}


pub fn new_state(tenant: TenantScope) -> State {
    State {
        table: CostTable {
            tenant,
            currency: None,
            accepted: 0,
            day_totals: BTreeMap::new(),
            by_account_service: BTreeMap::new(),
            by_tag: BTreeMap::new(),
            account_rows: BTreeMap::new(),
            seen_accounts: BTreeSet::new(),
            seen_days: None,
            days_out_of_range: 0,
            other: OtherBucket {
                cost: Decimal::ZERO,
                count: 0,
            },
            tag_other: OtherBucket {
                cost: Decimal::ZERO,
                count: 0,
            },
            skipped: BTreeMap::new(),
        },
        rows: 0,
        accounts: BTreeSet::new(),
        services: BTreeSet::new(),
        pairs: BTreeSet::new(),
    }
}


pub fn scan<Input: Read>(input: Input, limits: &Limits, tenant: TenantScope) -> Result<CostTable, CostError> {
    let mut reader: Reader<Input> = ReaderBuilder::new().from_reader(input);
    let columns = locate_columns(reader.headers()?)?;
    let mut state = new_state(tenant);
    reader.records().try_for_each(|result| absorb(&mut state, result, &columns, limits))?;
    Ok(state.table)
}


/// Reads at most `max_bytes` bytes of a FOCUS CSV export; the tenant is checked with core-pg's grammar.
pub fn read_focus<Input: Read>(reader: Input, limits: &Limits, tenant: &str) -> Result<CostTable, CostError> {
    let scope = tenant_scope(tenant)?;
    let mut limited = reader.take(limits.max_bytes.saturating_add(1));
    let table = scan(&mut limited, limits, scope)?;
    if limited.limit() == 0 {
        Err(CostError::TooLarge { limit: limits.max_bytes })
    } else {
        Ok(table)
    }
}
