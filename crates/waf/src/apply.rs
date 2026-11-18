use crate::admin::{id_status, open_admin_directory, AdminDirectory};
use crate::caddy::Admin;
use crate::cadir::{ca_root_path, directory_text_ok, directory_trusted, open_ca_directory, write_ca_root};
use crate::cli::place_ca_root;
use crate::error::{DeliverError, OpenError, WafError};
use crate::limits::{
    ADMIN_LISTEN_PREFIX, APPLIED_RESULT, APPLY_SECTION, DEADLINE_STATE_KEY, EPOCH_STATE_KEY, FILE_LABEL, FINAL_NAME, ID_HEX_CHARS, ID_PREFIX,
    LATE_PARAMETER, MAX_DEADLINE_SECONDS, MAX_FILE_BYTES, MAX_JSON_BYTES, MAX_REFUSED_LISTED, MIN_DEADLINE_SECONDS, PROC_FD_DIRECTORY,
    PROGRAM_STATE_KEY, REFUSED_STATE_KEY, RELOAD_STEP, RESULT_PARAMETER, ROUTES_STATE_KEY, SETTINGS_LABEL, STAGE_MODE, STAGE_PREFIX, STAGE_SUFFIX,
    START_DIFF, STATUS_OK, UNTRUSTED_PROGRAM, UNTRUSTED_SETTINGS, UNTRUSTED_SETTINGS_FILE, VALIDATE_STEP,
};
use crate::model::{Applied, ApplySettings, CommandStatus, Delivery};
use crate::render::render_reader;
use crate::types::RunnerFn;
use core_audit::model::Outcome;
use core_config::error::ConfigError;
use core_config::parse::{open_regular, parse_document, read_text_capped};
use core_config::reload::{current_config, open_engine, reload_entry, ReloadContext, ReloadEngine, Subscriber};
use core_config::trusted_dir::open_trusted_dir;
use core_config::types::{ConfigState, SharedAuditFn};
use data_encoding::HEXLOWER;
use rustix::fs::{fstat, fsync, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode, OFlags, RawMode, CWD};
use rustix::io::Errno;
use rustix::process::{geteuid, getpid};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, warn};


/// A settings problem; the text names the field, never its value.
pub fn refuse_setting(reason: String) -> ConfigError {
    ConfigError::WatchedFile {
        file: SETTINGS_LABEL.to_owned(),
        reason,
    }
}


/// A plain absolute path: the directory grammar plus an ASCII allowlist, so nothing can carry a separator, a space or a `|`.
pub fn path_text_ok(text: &str) -> bool {
    directory_text_ok(text)
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/-".contains(character))
}


/// Every path setting is a plain absolute path and the deadline is in range.
pub fn check_settings(settings: ApplySettings) -> Result<ApplySettings, ConfigError> {
    let paths = [
        ("routes_file", &settings.routes_file),
        ("out_dir", &settings.out_dir),
        ("caddy_program", &settings.caddy_program),
        ("admin_socket", &settings.admin_socket),
    ];
    paths.iter().try_for_each(|(name, value)| {
        path_text_ok(value)
            .then_some(())
            .ok_or_else(|| refuse_setting(format!("{name} is not a plain absolute path")))
    })?;
    (MIN_DEADLINE_SECONDS..=MAX_DEADLINE_SECONDS)
        .contains(&settings.deadline_seconds)
        .then_some(())
        .ok_or_else(|| refuse_setting(format!("deadline_seconds is outside {MIN_DEADLINE_SECONDS} to {MAX_DEADLINE_SECONDS}")))?;
    Ok(settings)
}


/// A failed system call as a settings refusal naming the setting and the error kind text.
pub fn errno_refusal(refusal: &str) -> impl Fn(Errno) -> ConfigError + '_ {
    move |errno| refuse_setting(format!("{refusal}: {}", io::Error::from(errno)))
}


/// Regular file, owned by root or this user, closed to group and others writes.
pub fn file_trusted(mode: RawMode, owner: u32, process_user: u32) -> bool {
    FileType::from_raw_mode(mode) == FileType::RegularFile && directory_trusted(mode, owner, process_user)
}


/// Opens `name` below the judged directory as an `O_PATH` anchor (no symlink followed, no driver run) and judges that handle.
pub fn judge_file(directory: &OwnedFd, name: &str, refusal: &str) -> Result<OwnedFd, ConfigError> {
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let anchor = openat(directory, name, flags, Mode::empty()).map_err(errno_refusal(refusal))?;
    let stat = fstat(&anchor).map_err(errno_refusal(refusal))?;
    file_trusted(stat.st_mode, stat.st_uid, geteuid().as_raw())
        .then_some(anchor)
        .ok_or_else(|| refuse_setting(refusal.to_owned()))
}


/// The judged anchor reopened for reading through `/proc/self/fd`, so the bytes read are those of the inode that was judged.
pub fn reopen_judged(anchor: &OwnedFd) -> Result<File, ConfigError> {
    let path = format!("{PROC_FD_DIRECTORY}{}", anchor.as_raw_fd());
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    openat(CWD, path.as_str(), flags, Mode::empty())
        .map(File::from)
        .map_err(errno_refusal(UNTRUSTED_SETTINGS_FILE))
}


/// The settings file read through its judged directory: parent walked from `/`, file anchored without following a symlink, owner and mode judged, bytes of that inode parsed.
pub fn load_trusted_settings_file(path: &Path) -> Result<ApplySettings, ConfigError> {
    let (parent, name) = path
        .parent()
        .zip(path.file_name().and_then(|name| name.to_str()))
        .ok_or_else(|| refuse_setting(UNTRUSTED_SETTINGS.to_owned()))?;
    let directory = open_trusted_dir(parent, geteuid().as_raw()).map_err(|failure| refuse_setting(format!("{UNTRUSTED_SETTINGS}: {failure}")))?;
    let anchor = judge_file(&directory, name, UNTRUSTED_SETTINGS_FILE)?;
    let label = path.display().to_string();
    let text = read_text_capped(&mut reopen_judged(&anchor)?, &label, MAX_FILE_BYTES)?;
    check_settings(parse_document::<ApplySettings>(&text, &label)?)
}


/// The Caddy program and every directory above it: owned by root or this user, no group or other write, no symlink.
pub fn judge_program(program: &str) -> Result<(), ConfigError> {
    let path = Path::new(program);
    let (parent, name) = path
        .parent()
        .zip(path.file_name().and_then(|name| name.to_str()))
        .ok_or_else(|| refuse_setting(UNTRUSTED_PROGRAM.to_owned()))?;
    let directory = open_ca_directory(parent).map_err(|_| refuse_setting(UNTRUSTED_PROGRAM.to_owned()))?;
    judge_file(&directory, name, UNTRUSTED_PROGRAM).map(drop)
}


/// The settings file judged and read at start and on every reload, then the Caddy program judged.
pub fn load_trusted_settings(path: &Path) -> Result<ApplySettings, ConfigError> {
    let settings = load_trusted_settings_file(path)?;
    judge_program(&settings.caddy_program)?;
    Ok(settings)
}


/// A render error as a reload refusal: a parse error keeps its position, anything else its fixed text.
pub fn config_error(failure: WafError) -> ConfigError {
    match failure {
        WafError::Config(inner) => inner,
        other => ConfigError::WatchedFile {
            file: FILE_LABEL.to_owned(),
            reason: other.to_string(),
        },
    }
}


/// A start-only setting (`routes_file`, `out_dir`, `admin_socket`) that differs from the running one is refused, never half applied.
pub fn check_start_only(running: &ApplySettings, loaded: &ApplySettings) -> Result<(), ConfigError> {
    let fields = [
        ("routes_file", running.routes_file == loaded.routes_file),
        ("out_dir", running.out_dir == loaded.out_dir),
        ("admin_socket", running.admin_socket == loaded.admin_socket),
    ];
    fields.iter().try_for_each(|(name, same)| {
        same.then_some(())
            .ok_or_else(|| refuse_setting(format!("{name} cannot change while running, restart waf_apply")))
    })
}


/// The object id Caddy indexes: a prefix and the first hex characters of the SHA-256 of the JSON without the id.
pub fn config_id(json_without_id: &str) -> String {
    let digest = HEXLOWER.encode(&Sha256::digest(json_without_id.as_bytes()));
    let kept: String = digest.chars().take(ID_HEX_CHARS).collect();
    format!("{ID_PREFIX}{kept}")
}


/// The current settings file, checked against the running start-only values, then the routes rendered under it.
pub fn load_applied(running: &ApplySettings, settings_file: &Path, epoch: &AtomicU64) -> Result<Applied, ConfigError> {
    let loaded = load_trusted_settings(settings_file)?;
    check_start_only(running, &loaded)?;
    render_applied_capped(&loaded, epoch.load(Ordering::SeqCst), MAX_JSON_BYTES)
}


/// Reads and renders the routes file; the JSON gets the Unix-socket admin endpoint with its object id and the CA root path of `out_dir`.
pub fn render_applied(settings: &ApplySettings, epoch: u64) -> Result<Applied, ConfigError> {
    render_applied_capped(settings, epoch, MAX_JSON_BYTES)
}


/// `render_applied` that refuses a configuration whose JSON exceeds `max_json_bytes`.
pub fn render_applied_capped(settings: &ApplySettings, epoch: u64, max_json_bytes: usize) -> Result<Applied, ConfigError> {
    let mut file = open_regular(Path::new(&settings.routes_file), FILE_LABEL)?;
    let mut rendered = render_reader(&mut file).map_err(config_error)?;
    let root_path = rendered
        .ca_root
        .as_ref()
        .map(|root| ca_root_path(Path::new(&settings.out_dir), root))
        .transpose()
        .map_err(config_error)?;
    place_ca_root(&mut rendered.config, root_path.as_deref());
    rendered.config.admin = Some(Admin {
        listen: format!("{ADMIN_LISTEN_PREFIX}{}", settings.admin_socket),
        id: None,
    });
    let plain = serde_json::to_string_pretty(&rendered.config)
        .map_err(WafError::from)
        .map_err(config_error)?;
    let id = config_id(&plain);
    rendered.config.admin = Some(Admin {
        listen: format!("{ADMIN_LISTEN_PREFIX}{}", settings.admin_socket),
        id: Some(id.clone()),
    });
    let json = serde_json::to_string_pretty(&rendered.config)
        .map_err(WafError::from)
        .map_err(config_error)?;
    let bytes = json.len();
    if bytes > max_json_bytes {
        Err(config_error(WafError::OutputTooLarge { bytes, max: max_json_bytes }))
    } else {
        Ok(Applied {
            id,
            epoch,
            settings: settings.clone(),
            json,
            ca_root: rendered.ca_root,
            refused: rendered.refused,
        })
    }
}


/// The refused routes as audited text: the count, then at most `MAX_REFUSED_LISTED` indexes and a visible cut.
pub fn refused_text(applied: &Applied) -> String {
    let count = applied.refused.len();
    let listed: Vec<String> = applied
        .refused
        .iter()
        .take(MAX_REFUSED_LISTED)
        .map(|refusal| refusal.index.to_string())
        .collect();
    let omitted = count.saturating_sub(MAX_REFUSED_LISTED);
    let cut = if omitted == 0 {
        String::new()
    } else {
        format!(" [{omitted} more omitted]")
    };
    format!("{count} refused: {}{cut}", listed.join(","))
}


pub fn applied_state(applied: &Applied) -> ConfigState {
    ConfigState::from([
        (ROUTES_STATE_KEY.to_owned(), applied.json.clone()),
        (REFUSED_STATE_KEY.to_owned(), refused_text(applied)),
        (EPOCH_STATE_KEY.to_owned(), applied.epoch.to_string()),
        (DEADLINE_STATE_KEY.to_owned(), applied.settings.deadline_seconds.to_string()),
        (PROGRAM_STATE_KEY.to_owned(), applied.settings.caddy_program.clone()),
    ])
}


/// The rendered file name must be free or a regular file: a symlink, FIFO or directory there is refused before anything is written.
pub fn check_target(directory: &OwnedFd) -> Result<(), DeliverError> {
    let acceptable = statat(directory, FINAL_NAME, AtFlags::SYMLINK_NOFOLLOW).map_or_else(
        |errno| errno == Errno::NOENT,
        |stat| FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
    );
    acceptable.then_some(()).ok_or(DeliverError::BadTarget)
}


/// Writes the staged file through the directory handle (no symlink, no FIFO open), owner-only, synced.
pub fn stage_file(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), DeliverError> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let created = openat(directory, name, flags, Mode::from_raw_mode(STAGE_MODE))?;
    let stat = fstat(&created)?;
    (FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile)
        .then_some(())
        .ok_or(DeliverError::BadTarget)?;
    let mut file = File::from(created);
    file.set_len(0)
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all())
        .map_err(DeliverError::Write)
}


/// Renames the staged file over the final name and syncs the directory.
pub fn publish(directory: &OwnedFd, name: &str) -> Result<(), DeliverError> {
    renameat(directory, name, directory, FINAL_NAME)
        .and_then(|()| fsync(directory))
        .map_err(|errno| DeliverError::Publish(errno.into()))
}


/// Removes the staged file; a failure is logged, never silent.
pub fn discard(directory: &OwnedFd, name: &str) {
    unlinkat(directory, name, AtFlags::empty()).unwrap_or_else(|errno| error!(%errno, "cannot remove the staged file"));
}


/// One Caddy command; only the exit status class is kept.
pub fn run_step(settings: &ApplySettings, runner: RunnerFn, step: &'static str, arguments: &[String]) -> Result<(), DeliverError> {
    let deadline = Duration::from_secs(settings.deadline_seconds);
    let status = runner(&settings.caddy_program, arguments, deadline).map_err(|source| DeliverError::Spawn { step, source })?;
    match status {
        CommandStatus::Success => Ok(()),
        CommandStatus::Failed(code) => Err(DeliverError::Failed { step, code }),
        CommandStatus::TimedOut => Err(DeliverError::TimedOut {
            step,
            seconds: settings.deadline_seconds,
        }),
    }
}


/// Asks the daemon whether it holds the object id of this configuration: 200 means a killed or failed `reload` client still got it applied.
pub fn confirm_late(settings: &ApplySettings, admin: &AdminDirectory, id: &str) -> Result<Delivery, DeliverError> {
    let answer = id_status(admin, id, Duration::from_secs(settings.deadline_seconds));
    match answer {
        Ok(STATUS_OK) => Ok(Delivery::Late),
        Ok(status) => {
            warn!(status, "caddy does not hold the new configuration, running configuration unknown");
            Err(DeliverError::Unknown { step: RELOAD_STEP })
        }
        Err(failure) => {
            let kind = failure.kind();
            warn!(?kind, "caddy admin socket gave no answer, running configuration unknown");
            Err(DeliverError::Unknown { step: RELOAD_STEP })
        }
    }
}


/// `caddy validate` then `caddy reload` of the same staged file, the admin endpoint named explicitly; a failed validate never reloads.
pub fn run_steps(settings: &ApplySettings, runner: RunnerFn, staged: &str, admin: &AdminDirectory, id: &str) -> Result<Delivery, DeliverError> {
    let address = format!("{ADMIN_LISTEN_PREFIX}{}", settings.admin_socket);
    let validate = ["validate", "--config", staged].map(str::to_owned);
    let reload = ["reload", "--config", staged, "--address", &address].map(str::to_owned);
    run_step(settings, runner, VALIDATE_STEP, &validate)?;
    let outcome = run_step(settings, runner, RELOAD_STEP, &reload);
    let ambiguous = matches!(outcome, Err(DeliverError::Failed { .. } | DeliverError::TimedOut { .. }));
    if ambiguous {
        confirm_late(settings, admin, id)
    } else {
        outcome.map(|()| Delivery::Confirmed)
    }
}


/// Stages, validates and loads one rendered file, then makes it the final file; on any failure the staged file goes and the old one stays.
pub fn deliver(applied: &Applied, runner: RunnerFn) -> Result<Delivery, DeliverError> {
    let settings = &applied.settings;
    let admin = open_admin_directory(&settings.admin_socket)?;
    let out_dir = Path::new(&settings.out_dir);
    let directory = open_trusted_dir(out_dir, geteuid().as_raw())?;
    check_target(&directory)?;
    applied
        .ca_root
        .iter()
        .try_for_each(|root| write_ca_root(out_dir, root))
        .map_err(DeliverError::CaRoot)?;
    let name = format!("{STAGE_PREFIX}{}{STAGE_SUFFIX}", getpid().as_raw_nonzero());
    let staged = format!("{}/{name}", settings.out_dir);
    let outcome = stage_file(&directory, &name, applied.json.as_bytes())
        .and_then(|()| run_steps(settings, runner, &staged, &admin, &applied.id))
        .and_then(|delivery| publish(&directory, &name).map(|()| delivery));
    outcome.inspect_err(|_| discard(&directory, &name))
}


/// The hook of the engine: a refusal keeps the previous rendered file; an outcome that may differ from the engine state moves the epoch.
pub fn caddy_subscriber(runner: RunnerFn, late: Arc<AtomicBool>, epoch: Arc<AtomicU64>) -> Subscriber<Applied> {
    Subscriber {
        section: APPLY_SECTION.to_owned(),
        validate: Box::new(move |applied| {
            let delivery = deliver(applied, runner);
            match &delivery {
                Ok(Delivery::Late) => late.store(true, Ordering::SeqCst),
                Err(DeliverError::Unknown { .. } | DeliverError::Publish(_)) => {
                    epoch.fetch_add(1, Ordering::SeqCst);
                }
                Ok(Delivery::Confirmed) | Err(_) => (),
            }
            delivery.map(|_| ()).map_err(Into::into)
        }),
        apply: Box::new(|_applied| ()),
    }
}


/// The audit sink: `late: true` on a read-back `applied` entry, the flag cleared on every entry, the epoch moved when an applied entry is lost.
pub fn late_audit(audit: Box<SharedAuditFn>, late: Arc<AtomicBool>, epoch: Arc<AtomicU64>) -> Box<SharedAuditFn> {
    Box::new(move |mut entry| {
        let applied = entry.parameters.get(RESULT_PARAMETER).is_some_and(|value| value == APPLIED_RESULT);
        let was_late = late.swap(false, Ordering::SeqCst);
        if applied && was_late {
            entry.parameters.insert(LATE_PARAMETER.to_owned(), "true".to_owned());
        }
        let result = audit(entry);
        if applied && result.is_err() {
            epoch.fetch_add(1, Ordering::SeqCst);
        }
        result
    })
}


/// Loads the settings and the first configuration, delivers it (any refusal fails the start) and audits it as applied; later reloads do the same.
pub fn open_apply(
    settings_file: &Path,
    runner: RunnerFn,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<Applied>, OpenError> {
    let running = load_trusted_settings(settings_file)?;
    let epoch = Arc::new(AtomicU64::new(0));
    let late = Arc::new(AtomicBool::new(false));
    let loader_epoch = Arc::clone(&epoch);
    let loader_file: PathBuf = settings_file.to_path_buf();
    let engine = open_engine(
        Box::new(move || load_applied(&running, &loader_file, &loader_epoch)),
        applied_state,
        vec![caddy_subscriber(runner, Arc::clone(&late), Arc::clone(&epoch))],
        late_audit(audit, Arc::clone(&late), epoch),
        context,
    )?;
    let delivery = deliver(&current_config(&engine), runner)?;
    late.store(delivery == Delivery::Late, Ordering::SeqCst);
    let entry = reload_entry(
        &engine.context,
        Outcome::Success,
        [(RESULT_PARAMETER, APPLIED_RESULT.to_owned()), ("diff", START_DIFF.to_owned())],
    );
    (engine.audit)(entry).map_err(OpenError::Audit)?;
    Ok(engine)
}
