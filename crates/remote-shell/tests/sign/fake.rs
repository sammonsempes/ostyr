use core_pg::scope::{tenant_of, TenantScope};
use remote_shell::error::StoreError;
use remote_shell::sign::{CLAIM_SQL, SEQUENCE_SQL, SIGN_STATE_SQL};
use remote_shell::store_model::{Cell, Param, SessionRow, Statement};
use remote_shell::types::Row;
use std::cell::RefCell;
use std::future::{ready, Ready};


pub struct Stored {
    pub tenant: String,
    pub row: SessionRow,
}


pub struct Signed {
    pub tenant: String,
    pub session_id: String,
    pub agent_id: String,
    pub approvers: String,
    pub max_seconds: i64,
    pub idle_seconds: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
    pub sequence: Option<i64>,
}


#[derive(Clone, Copy)]
pub enum Edit {
    Unreadable(usize),
    Null(usize),
    Truncate(usize),
}


pub fn apply(edit: Edit, row: Row) -> Row {
    match edit {
        Edit::Unreadable(column) => row
            .into_iter()
            .enumerate()
            .map(|(index, cell)| if index == column { Cell::Unreadable } else { cell })
            .collect(),
        Edit::Null(column) => row
            .into_iter()
            .enumerate()
            .map(|(index, cell)| if index == column { Cell::Null } else { cell })
            .collect(),
        Edit::Truncate(length) => row.into_iter().take(length).collect(),
    }
}


#[derive(Default)]
pub struct Db {
    pub sessions: Vec<Stored>,
    pub signed: Vec<Signed>,
    pub statements: Vec<&'static str>,
    pub fail_on: Option<&'static str>,
    pub refuse_claim: bool,
    pub empty_sequence: bool,
    pub edit_state: Option<Edit>,
}


pub fn injected() -> StoreError {
    StoreError::BadRow { column: "injected" }
}


pub fn claim_rows(db: &mut Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    match params {
        [Param::Text(session), Param::Text(requester), Param::Text(asset), Param::Text(ticket), Param::Int(opened_at), Param::Text(agent), Param::Text(approvers), Param::Int(max_seconds), Param::Int(idle_seconds), Param::Int(issued_at), Param::Int(expires_at), Param::Text(key), Param::Int(cap)] =>
        {
            let pending = db
                .signed
                .iter()
                .filter(|entry| entry.tenant == tenant && entry.expires_at >= *issued_at)
                .count();
            let open = db.sessions.iter().any(|stored| {
                stored.tenant == tenant
                    && stored.row.session_id == *session
                    && stored.row.closed_at.is_none()
                    && stored.row.requester == *requester
                    && stored.row.asset == *asset
                    && stored.row.ticket == *ticket
                    && stored.row.opened_at == *opened_at
            });
            let signed = db.signed.iter().any(|entry| entry.tenant == tenant && entry.session_id == *session);
            if db.refuse_claim || !open || signed || i64::try_from(pending).unwrap_or(i64::MAX) >= *cap {
                Ok(Vec::new())
            } else {
                db.signed.push(Signed {
                    tenant: tenant.to_owned(),
                    session_id: session.clone(),
                    agent_id: agent.clone(),
                    approvers: approvers.clone(),
                    max_seconds: *max_seconds,
                    idle_seconds: *idle_seconds,
                    issued_at: *issued_at,
                    expires_at: *expires_at,
                    key_id: key.clone(),
                    sequence: None,
                });
                Ok(vec![vec![Cell::Text(session.clone())]])
            }
        }
        _ => Err(injected()),
    }
}


pub fn state_rows(db: &Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    match params {
        [Param::Text(session), Param::Int(issued_at)] => {
            let unexpired = db.signed.iter().filter(|entry| entry.tenant == tenant && entry.expires_at >= *issued_at);
            let pending = i64::try_from(unexpired.count()).unwrap_or(i64::MAX);
            let signed = db
                .signed
                .iter()
                .find(|entry| entry.tenant == tenant && entry.session_id == *session)
                .map_or(Cell::Null, |entry| Cell::Text(entry.session_id.clone()));
            Ok(db
                .sessions
                .iter()
                .filter(|stored| stored.tenant == tenant && stored.row.session_id == *session)
                .map(|stored| {
                    let row = vec![
                        stored.row.closed_at.map_or(Cell::Null, Cell::Int),
                        Cell::Int(stored.row.opened_at),
                        Cell::Text(stored.row.requester.clone()),
                        Cell::Text(stored.row.asset.clone()),
                        Cell::Text(stored.row.ticket.clone()),
                        signed.clone(),
                        Cell::Int(pending),
                    ];
                    db.edit_state.map_or(row.clone(), |edit| apply(edit, row))
                })
                .collect())
        }
        _ => Err(injected()),
    }
}


pub fn sequence_rows(db: &mut Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    match params {
        [Param::Text(session), Param::Int(sequence)] => {
            let empty = db.empty_sequence;
            let found = db
                .signed
                .iter_mut()
                .find(|entry| entry.tenant == tenant && entry.session_id == *session && entry.sequence.is_none() && !empty);
            Ok(found.map_or(Vec::new(), |entry| {
                entry.sequence = Some(*sequence);
                vec![vec![Cell::Text(entry.session_id.clone())]]
            }))
        }
        _ => Err(injected()),
    }
}


pub fn handle(db: &RefCell<Db>, scope: &TenantScope, statement: Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    let mut state = db.borrow_mut();
    state.statements.push(statement.sql);
    let tenant = tenant_of(scope);
    let outcome = if state.fail_on == Some(statement.sql) {
        Err(injected())
    } else if statement.sql == CLAIM_SQL {
        claim_rows(&mut state, tenant, &statement.params)
    } else if statement.sql == SIGN_STATE_SQL {
        state_rows(&state, tenant, &statement.params)
    } else if statement.sql == SEQUENCE_SQL {
        sequence_rows(&mut state, tenant, &statement.params)
    } else {
        Err(injected())
    };
    ready(outcome)
}
