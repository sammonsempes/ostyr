use crate::caddy::Admin;
use crate::cadir::{ca_root_path, directory_text_ok, write_ca_root};
use crate::cli::place_ca_root;
use crate::error::{DeliverError, OpenError, WafError};
use crate::limits::{
    ADMIN_LISTEN_PREFIX, APPLY_SECTION, FILE_LABEL, FINAL_NAME, MAX_DEADLINE_SECONDS, MAX_JSON_BYTES, MAX_REFUSED_LISTED, MIN_DEADLINE_SECONDS,
    REFUSED_STATE_KEY, RELOAD_STEP, ROUTES_STATE_KEY, SETTINGS_LABEL, STAGE_MODE, STAGE_PREFIX, STAGE_SUFFIX, VALIDATE_STEP,
};
use crate::model::{Applied, ApplySettings, CommandStatus};
use crate::render::render_reader;
use crate::types::RunnerFn;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::parse::open_regular;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::trusted_dir::open_trusted_dir;
use core_config::types::{ConfigState, SharedAuditFn};
use rustix::fs::{fstat, fsync, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::{geteuid, getpid};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;
use tracing::error;


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


pub fn load_settings(path: &Path) -> Result<ApplySettings, ConfigError> {
    check_settings(load_file::<ApplySettings>(path)?)
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


/// Reads and renders the routes file; the JSON gets the Unix-socket admin endpoint and the CA root path of `out_dir`.
pub fn render_applied(settings: &ApplySettings) -> Result<Applied, ConfigError> {
    render_applied_capped(settings, MAX_JSON_BYTES)
}


/// `render_applied` that refuses a configuration whose JSON exceeds `max_json_bytes`.
pub fn render_applied_capped(settings: &ApplySettings, max_json_bytes: usize) -> Result<Applied, ConfigError> {
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
    });
    let json = serde_json::to_string_pretty(&rendered.config)
        .map_err(WafError::from)
        .map_err(config_error)?;
    let bytes = json.len();
    if bytes > max_json_bytes {
        Err(config_error(WafError::OutputTooLarge { bytes, max: max_json_bytes }))
    } else {
        Ok(Applied {
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
    renameat(directory, name, directory, FINAL_NAME)?;
    Ok(fsync(directory)?)
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


/// `caddy validate` then `caddy reload` of the same staged file, the admin endpoint named explicitly; a failed validate never reloads.
pub fn run_steps(settings: &ApplySettings, runner: RunnerFn, staged: &str) -> Result<(), DeliverError> {
    let address = format!("{ADMIN_LISTEN_PREFIX}{}", settings.admin_socket);
    let validate = ["validate", "--config", staged].map(str::to_owned);
    let reload = ["reload", "--config", staged, "--address", &address].map(str::to_owned);
    run_step(settings, runner, VALIDATE_STEP, &validate)?;
    run_step(settings, runner, RELOAD_STEP, &reload)
}


/// Stages, validates and loads one rendered file, then makes it the final file; on any failure the staged file goes and the old one stays.
pub fn deliver(settings: &ApplySettings, applied: &Applied, runner: RunnerFn) -> Result<(), DeliverError> {
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
        .and_then(|()| run_steps(settings, runner, &staged))
        .and_then(|()| publish(&directory, &name));
    outcome.inspect_err(|_| discard(&directory, &name))
}


/// The hook of the engine: a refusal here keeps the running configuration and the previous rendered file.
pub fn caddy_subscriber(settings: ApplySettings, runner: RunnerFn) -> Subscriber<Applied> {
    Subscriber {
        section: APPLY_SECTION.to_owned(),
        validate: Box::new(move |applied| deliver(&settings, applied, runner).map_err(Into::into)),
        apply: Box::new(|_applied| ()),
    }
}


/// Renders and delivers the first configuration (any refusal fails the start), then returns the engine whose reloads do the same.
pub fn open_apply(
    settings: ApplySettings,
    runner: RunnerFn,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<Applied>, OpenError> {
    let checked = check_settings(settings)?;
    let loader_settings = checked.clone();
    let engine = open_engine(
        Box::new(move || render_applied(&loader_settings)),
        applied_state,
        vec![caddy_subscriber(checked.clone(), runner)],
        audit,
        context,
    )?;
    deliver(&checked, &current_config(&engine), runner)?;
    Ok(engine)
}
