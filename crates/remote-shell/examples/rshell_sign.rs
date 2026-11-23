//! Usage: `rshell_sign <pg.yaml> <tenant> <seed-hex> <key-id> <sequence-dir> <session> <asset=agent> <low|critical> [<approver>]`; the live proof of the `OpenShell` signer.
use agent_command::model::KeyClass;
use agent_command::sign::{memory_signer, os_random};
use cmdb::model::Criticality;
use core_auth::types::{RoleCatalog, RoleSet};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use ed25519_dalek::SigningKey;
use remote_shell::agent_map::AgentMap;
use remote_shell::backend::pg_execute;
use remote_shell::error::StoreError;
use remote_shell::open::{Approval, Evidence, MfaProof, PERMISSION_REMOTE_SHELL_APPROVE, PERMISSION_REMOTE_SHELL_OPEN};
use remote_shell::policy::ValidatedPolicy;
use remote_shell::serve::get_session;
use remote_shell::sign::sign_open_shell;
use remote_shell::sign_model::{SignInputs, Signing};
use remote_shell::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use remote_shell::store_model::{SessionRow, Statement};
use remote_shell::types::{BoxedCause, Row};
use std::collections::BTreeMap;
use std::io::{stderr, stdout, ErrorKind, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_postgres::Client;


const USAGE: &str = "usage: rshell_sign <pg.yaml> <tenant> <seed-hex> <key-id> <sequence-dir> <session> <asset=agent> <low|critical> [<approver>]";


const DEADLINE: Duration = Duration::from_secs(30);


const SEED_BYTES: usize = 32;


const HEX_RADIX: u32 = 16;


const HEX_DIGITS_PER_BYTE: usize = 2;


async fn execute(client: &Client, scope: TenantScope, statement: Statement) -> Result<Vec<Row>, StoreError> {
    pg_execute(client, DEADLINE, scope, statement).await
}


fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}


fn seed_of(text: &str) -> Result<[u8; SEED_BYTES], Box<dyn std::error::Error>> {
    let bytes = text
        .as_bytes()
        .chunks(HEX_DIGITS_PER_BYTE)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair)?, HEX_RADIX).map_err(Box::<dyn std::error::Error>::from))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(<[u8; SEED_BYTES]>::try_from(bytes.as_slice())?)
}


fn next_in_file(directory: &Path, agent: &str) -> Result<u64, BoxedCause> {
    let file = directory.join(format!("{agent}.seq"));
    let text = std::fs::read_to_string(&file).or_else(|error| {
        if error.kind() == ErrorKind::NotFound {
            Ok("0".to_owned())
        } else {
            Err(error)
        }
    })?;
    let next = text.trim().parse::<u64>()? + 1;
    std::fs::write(&file, next.to_string())?;
    Ok(next)
}


fn catalog() -> RoleCatalog {
    [("operator", PERMISSION_REMOTE_SHELL_OPEN), ("approver", PERMISSION_REMOTE_SHELL_APPROVE)]
        .into_iter()
        .map(|(role, permission)| (role.to_owned(), [permission.to_owned()].into_iter().collect()))
        .collect()
}


fn evidence_of(row: &SessionRow, approver: Option<&String>, now: i64) -> Evidence {
    Evidence {
        mfa: Some(MfaProof {
            request_id: row.session_id.clone(),
            tenant: String::new(),
            subject: row.requester.clone(),
            verified_at: now,
        }),
        approvals: approver
            .map(|name| Approval {
                request_id: row.session_id.clone(),
                tenant: String::new(),
                approver: name.clone(),
                approved_at: now,
            })
            .into_iter()
            .collect(),
        approver_roles: approver
            .map(|name| (name.clone(), ["approver".to_owned()].into_iter().collect::<RoleSet>()))
            .into_iter()
            .collect::<BTreeMap<String, RoleSet>>(),
    }
}


fn with_tenant(evidence: Evidence, tenant: &str) -> Evidence {
    Evidence {
        mfa: evidence.mfa.map(|proof| MfaProof {
            tenant: tenant.to_owned(),
            ..proof
        }),
        approvals: evidence
            .approvals
            .into_iter()
            .map(|approval| Approval {
                tenant: tenant.to_owned(),
                ..approval
            })
            .collect(),
        approver_roles: evidence.approver_roles,
    }
}


async fn scenario(settings_file: &Path, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args {
        [tenant, seed, key_id, directory, session, mapping, level, approver @ ..] => {
            let names = Names {
                tenant,
                seed,
                key_id,
                directory,
                session,
                mapping,
                level,
            };
            sign_one(settings_file, &names, approver.first()).await
        }
        _ => Err(USAGE.into()),
    }
}


struct Names<'text> {
    tenant: &'text str,
    seed: &'text str,
    key_id: &'text str,
    directory: &'text str,
    session: &'text str,
    mapping: &'text str,
    level: &'text str,
}


async fn sign_one(settings_file: &Path, names: &Names<'_>, approver: Option<&String>) -> Result<(), Box<dyn std::error::Error>> {
    let Names {
        tenant,
        seed,
        key_id,
        directory,
        session,
        mapping,
        level,
    } = *names;
    let (asset, agent) = mapping.split_once('=').ok_or(USAGE)?;
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let scope = tenant_scope(tenant)?;
    let mut exec = |bound: &TenantScope, statement: Statement| execute(&client, bound.clone(), statement);
    let row = get_session(&mut exec, &scope, session).await?.ok_or("unknown session")?;
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let agents = AgentMap {
        tenant: tenant.to_owned(),
        agents: BTreeMap::from([(asset.to_owned(), agent.to_owned())]),
    };
    let policy = ValidatedPolicy::default();
    let catalog = catalog();
    let roles: RoleSet = ["operator".to_owned()].into_iter().collect();
    let evidence = with_tenant(evidence_of(&row, approver, now), tenant);
    let inputs = SignInputs {
        policy: &policy,
        catalog: &catalog,
        requester_roles: &roles,
        criticality: Some(if level == "critical" { Criticality::Critical } else { Criticality::Low }),
        evidence: &evidence,
    };
    let signer = memory_signer(SigningKey::from_bytes(&seed_of(seed)?));
    let gate = agent_channel::shell_gate::new_gate(Box::new(move || now.unsigned_abs()));
    let fillers = std::env::var("RSHELL_SIGN_FILL_GATE").map_or(Ok(0), |text| text.parse::<usize>())?;
    (0..fillers)
        .try_for_each(|index| agent_channel::shell_gate::gate_add(&gate, tenant, &format!("filler-{index}"), "filler", now.unsigned_abs() + 1, 1))?;
    let mut allocate = |agent_id: &str, _class: KeyClass| next_in_file(Path::new(directory), agent_id);
    let mut signing = Signing {
        key_id,
        next_sequence: &mut allocate,
        fill: os_random,
        signer: &*signer,
        gate: &gate,
    };
    let signed = sign_open_shell(&mut exec, &scope, &row, &inputs, &agents, &mut signing, now).await?;
    writeln!(stdout(), "signed agent={} envelope={}", signed.identity.agent_id, hex(&signed.envelope))?;
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((settings, rest)) => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), rest)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "refused: {error}").map(|()| ExitCode::FAILURE),
            }
        }
        None => writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE),
    }
}
