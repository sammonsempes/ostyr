use core_audit::error::AuditError;
use core_audit::log::{append, open_file_log};
use core_audit::model::{Actor, ActorKind};
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::SharedAuditFn;
use policy_validator::audit::ValidationContext;
use policy_validator::model::{
    Engine, Evidence, Exclusion, Impact, ObservedImage, Proposal, Reason, Scope, Selector, SelectorKind, Severity, Verdict,
};
use policy_validator::policy::{compile, LoadedPolicy, Policy};
use policy_validator::reload::{policy_loader, policy_state};
use policy_validator::rules::validate;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;


pub const BPF_AGENT_INDEX: usize = 18;


pub const TETRAGON_SENSOR_INDEX: usize = 8;


pub const OSQUERYD_SENSOR_INDEX: usize = 6;


pub const OSTYR_SENSOR_INDEX: usize = 11;


pub const OSTYR_AGENT_INDEX: usize = 2;


pub const VERDICTS: u32 = 8;


pub const DAYS: u32 = 4;


pub const ENDPOINTS: u32 = 6;


pub const LIFETIME: u32 = 30;


pub const DETECTIONS: u32 = 3;


pub const NEED_VERDICTS: u32 = 5;


pub const NEED_DAYS: u32 = 3;


pub const MAX_LIFETIME: u32 = 90;


pub const YEAR: u32 = 365;


pub const RAISED_MIN: u32 = 10;


pub const HASH_LENGTH: usize = 64;


pub const HASH_PAIRS: usize = 32;


pub const TECHNIQUE: &str = "T1059";


pub const GOOD_PATH: &str = "/srv/app/bin/tool";


pub const GOOD_WINDOWS_PATH: &str = r"C:\Program Files\Vendor\tool.exe";


pub fn hash() -> String {
    "ab".repeat(HASH_PAIRS)
}


pub fn image(name: &str) -> ObservedImage {
    ObservedImage {
        path: format!("/srv/app/bin/{}", name.rsplit(['/', '\\']).next().unwrap_or(name)),
        sha256: hash(),
        name: name.to_owned(),
        original_file_name: None,
        os_component: false,
        security_sensor: false,
        writable_by_non_admin: false,
    }
}


pub fn evidence() -> Evidence {
    Evidence {
        benign_verdicts: VERDICTS,
        distinct_days: DAYS,
        distinct_endpoints: ENDPOINTS,
        role_match: true,
        original_severity: Severity::Low,
        honeytoken_linked: false,
        signed_by_trusted: true,
        known_hash: None,
        observed_images: vec![image("tool")],
    }
}


pub fn impact() -> Impact {
    Impact {
        techniques: vec![TECHNIQUE.to_owned()],
        detections: BTreeMap::from([(TECHNIQUE.to_owned(), DETECTIONS)]),
    }
}


pub fn bound_image(kind: SelectorKind, value: &str) -> ObservedImage {
    let executable = if kind == SelectorKind::CommandLine {
        value.split(' ').next().unwrap_or(value)
    } else {
        value
    };
    let path = if kind == SelectorKind::Hash { "/srv/app/bin/tool" } else { executable };
    ObservedImage {
        path: path.to_owned(),
        sha256: if kind == SelectorKind::Hash { value.to_owned() } else { hash() },
        name: path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned(),
        ..image("tool")
    }
}


pub fn exclusion(scope: Scope, kind: SelectorKind, value: &str) -> Exclusion {
    Exclusion {
        engine: Engine::Sigma,
        scope,
        selector: Selector {
            kind,
            value: value.to_owned(),
        },
        lifetime_days: LIFETIME,
        evidence: Evidence {
            observed_images: vec![
                if kind == SelectorKind::Hash || (scope == Scope::SingleEndpoint && kind != SelectorKind::Signer) {
                    bound_image(kind, value)
                } else {
                    image("tool")
                },
            ],
            ..evidence()
        },
        impact: impact(),
    }
}


pub fn loaded() -> Result<LoadedPolicy, Box<dyn Error>> {
    Ok(compile(Policy::default(), "test-hash".to_owned())?)
}


pub fn verdict_for(proposal: Exclusion) -> Result<Verdict, Box<dyn Error>> {
    Ok(validate(&loaded()?, &Proposal::Exclusion(proposal)))
}


pub fn reasons_for(proposal: Exclusion) -> Result<Vec<Reason>, Box<dyn Error>> {
    Ok(verdict_for(proposal)?.reasons)
}


pub fn probe(scope: Scope, kind: SelectorKind, value: &str) -> Result<Vec<Reason>, Box<dyn Error>> {
    reasons_for(exclusion(scope, kind, value))
}


pub fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "example".to_owned(),
        module: "policy-validator".to_owned(),
        target: "policy.yaml".to_owned(),
        request_id: "test-reload".to_owned(),
    }
}


pub fn validation_context() -> ValidationContext {
    ValidationContext {
        actor: Actor {
            kind: ActorKind::Ai,
            id: "tester".to_owned(),
        },
        tenant: "example".to_owned(),
        request_id: "req".to_owned(),
    }
}


pub fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


pub struct Bench {
    pub _dir: TempDir,
    pub policy_file: PathBuf,
    pub audit_file: PathBuf,
    pub engine: ReloadEngine<LoadedPolicy>,
}


pub fn bench(policy_text: &str) -> Result<Bench, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let policy_file = dir.path().join("policy.yaml");
    let audit_file = dir.path().join("audit.log");
    fs::write(&policy_file, policy_text)?;
    let log = open_file_log(&audit_file)?;
    let audit: Box<SharedAuditFn> = Box::new(move |entry| append(&log, entry));
    let engine = open_engine(policy_loader(policy_file.clone()), policy_state, Vec::new(), audit, context())?;
    Ok(Bench {
        _dir: dir,
        policy_file,
        audit_file,
        engine,
    })
}


pub fn failing_audit_engine() -> Result<(TempDir, ReloadEngine<LoadedPolicy>), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let policy_file = dir.path().join("policy.yaml");
    fs::write(&policy_file, "{}")?;
    let audit: Box<SharedAuditFn> = Box::new(|_entry| Err(AuditError::LogPoisoned));
    let engine = open_engine(policy_loader(policy_file), policy_state, Vec::new(), audit, context())?;
    Ok((dir, engine))
}


pub struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write refused"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush refused"))
    }
}


pub struct NewlineFails;


impl Write for NewlineFails {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.contains(&b'\n') {
            Err(io::Error::other("newline refused"))
        } else {
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


pub struct FailingReader;


impl io::Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read refused"))
    }
}
