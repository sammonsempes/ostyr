//! Live proof driver for T961: runs `ostyr-auth` through the break-glass scenario; usage `breakglass_proof <ostyr-auth> <directory> <rp id> <origin>`.

use data_encoding::BASE64URL_NOPAD;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::io::{stdout, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use webauthn_authenticator_rs::prelude::{Url, WebauthnAuthenticator};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;


const PASSWORD: &str = "correct-horse-battery";


const SOURCE: &str = "10.0.0.7";


const REPLY_PARTS: usize = 3;


const KEY_BYTES: usize = 32;


const KEY_FILL: u8 = 9;


const WRONG_ATTEMPTS: usize = 6;


const UUID_BYTES: usize = 16;


#[cfg(unix)]
const OWNER_ONLY: u32 = 0o600;


const USER_HANDLE_DOMAIN: &str = "ostyr-webauthn-user:";


const ROLES: &str = r#"[{"name":"glass","permissions":["events.read","policy.break_glass","policy.webauthn_required"]}]"#;


struct Tool {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}


struct Rig {
    binary: String,
    directory: String,
    origin: Url,
}


#[cfg(unix)]
fn private_file(path: &Path, content: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, content)?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(OWNER_ONLY))?;
    Ok(())
}


#[cfg(not(unix))]
fn private_file(path: &Path, content: &[u8]) -> Result<(), Box<dyn Error>> {
    Ok(fs::write(path, content)?)
}


fn file_in(rig: &Rig, name: &str) -> String {
    Path::new(&rig.directory).join(name).display().to_string()
}


fn prepare(rig: &Rig, rp_id: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&rig.directory)?;
    private_file(Path::new(&file_in(rig, "key")), &[KEY_FILL; KEY_BYTES])?;
    private_file(Path::new(&file_in(rig, "words")), b"password1234\n")?;
    private_file(Path::new(&file_in(rig, "roles.json")), ROLES.as_bytes())?;
    let config = format!("rp_id: {rp_id}\nrp_origin: {}\nrp_name: Ostyr\n", rig.origin);
    private_file(Path::new(&file_in(rig, "webauthn.yaml")), config.as_bytes())
}


fn spawn(rig: &Rig) -> Result<Tool, Box<dyn Error>> {
    let mut child = Command::new(&rig.binary)
        .args(["accounts.json", "audit.log", "key", "words", "webauthn.yaml", "roles.json"].map(|name| file_in(rig, name)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let input = child.stdin.take().ok_or("no stdin")?;
    let output = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    Ok(Tool { child, input, output })
}


fn read_reply(tool: &mut Tool) -> Result<String, Box<dyn Error>> {
    let mut line = String::new();
    tool.output.read_line(&mut line)?;
    Ok(line.trim().to_owned())
}


fn ask(tool: &mut Tool, command: &str) -> Result<String, Box<dyn Error>> {
    writeln!(tool.input, "{command}")?;
    tool.input.flush()?;
    read_reply(tool)
}


fn finish(mut tool: Tool) -> Result<(), Box<dyn Error>> {
    drop(tool.input);
    tool.child.wait()?;
    Ok(())
}


fn say(text: &str) -> Result<(), Box<dyn Error>> {
    Ok(writeln!(stdout(), "{text}")?)
}


fn expect(label: &str, holds: bool, reply: &str) -> Result<(), Box<dyn Error>> {
    say(&format!("{} {label}: {reply}", if holds { "PASS" } else { "FAIL" }))?;
    if holds {
        Ok(())
    } else {
        Err(format!("check failed: {label}").into())
    }
}


fn split_reply(reply: &str) -> Result<(String, String), Box<dyn Error>> {
    let mut parts = reply.splitn(REPLY_PARTS, ' ');
    parts.next();
    let identifier = parts.next().ok_or("no identifier")?.to_owned();
    Ok((identifier, parts.next().ok_or("no document")?.to_owned()))
}


fn user_handle(username: &str) -> String {
    let digest = Sha256::digest(format!("{USER_HANDLE_DOMAIN}{username}").as_bytes());
    let bytes: Vec<u8> = digest.iter().take(UUID_BYTES).copied().collect();
    BASE64URL_NOPAD.encode(&bytes)
}


fn set_at(document: &mut Value, pointer: &str, replacement: Value) -> Result<(), Box<dyn Error>> {
    *document.pointer_mut(pointer).ok_or("missing member")? = replacement;
    Ok(())
}


fn register(rig: &Rig, tool: &mut Tool, soft: &mut SoftPasskey, (token, user): (&str, &str)) -> Result<String, Box<dyn Error>> {
    let (challenge, options) = split_reply(&ask(tool, &format!("wa-register-start {token} {user}"))?)?;
    let response = soft.do_registration(rig.origin.clone(), serde_json::from_str(&options)?)?;
    let json = serde_json::to_string(&response)?;
    let reply = ask(tool, &format!("wa-register-finish {token} {user} {challenge} soft-key {json}"))?;
    Ok(reply.strip_prefix("ok ").ok_or("registration refused")?.to_owned())
}


fn passkey_login(
    rig: &Rig,
    tool: &mut Tool,
    soft: &mut SoftPasskey,
    (credential, user, source): (&str, &str, &str),
) -> Result<String, Box<dyn Error>> {
    let (challenge, options) = split_reply(&ask(tool, &format!("passkey-start {source}"))?)?;
    let mut request: Value = serde_json::from_str(&options)?;
    set_at(
        &mut request,
        "/publicKey/allowCredentials",
        json!([{ "type": "public-key", "id": credential }]),
    )?;
    let mut response = serde_json::to_value(soft.do_authentication(rig.origin.clone(), serde_json::from_value(request)?)?)?;
    set_at(&mut response, "/response/userHandle", json!(user_handle(user)))?;
    ask(tool, &format!("wa-login-finish {challenge} {source} {response}"))
}


fn administrator_token(tool: &mut Tool) -> Result<String, Box<dyn Error>> {
    writeln!(tool.input, "bootstrap admin {PASSWORD}")?;
    let secret_line = read_reply(tool)?;
    read_reply(tool)?;
    let secret = secret_line.strip_prefix("secret ").ok_or("no secret")?;
    let code = ask(tool, &format!("totp {secret}"))?;
    let logged = ask(tool, &format!("login admin {PASSWORD} {SOURCE} {code}"))?;
    Ok(logged.strip_prefix("ok ").ok_or("admin login refused")?.to_owned())
}


fn scenario(rig: &Rig, soft: &mut SoftPasskey) -> Result<(), Box<dyn Error>> {
    let mut tool = spawn(rig)?;
    let admin = administrator_token(&mut tool)?;
    let created = ask(&mut tool, &format!("create {admin} glass {PASSWORD} reader"))?;
    expect("account created as a plain reader", created == "ok", &created)?;
    let own = ask(&mut tool, &format!("login glass {PASSWORD} 10.0.0.9"))?;
    let own_token = own.strip_prefix("ok ").ok_or("glass login refused")?.to_owned();
    let credential = register(rig, &mut tool, soft, (&own_token, "glass"))?;
    expect("the account registers its own passkey", !credential.is_empty(), &credential)?;
    let granted = ask(&mut tool, &format!("roles {admin} glass glass"))?;
    expect("the manager grants the break-glass role", granted == "ok", &granted)?;
    let status = ask(&mut tool, &format!("breakglass-status {admin}"))?;
    expect("breakglass-status lists the account", status.starts_with("glass 1 never"), &status)?;
    (0..WRONG_ATTEMPTS).try_for_each(|index| -> Result<(), Box<dyn Error>> {
        ask(&mut tool, &format!("login glass wrong-password-{index} 10.1.0.{index}"))?;
        Ok(())
    })?;
    let locked = ask(&mut tool, &format!("login glass {PASSWORD} 10.2.0.1"))?;
    expect("six wrong passwords lock the account", locked == "error invalid credentials", &locked)?;
    let crisis = passkey_login(rig, &mut tool, soft, (&credential, "glass", SOURCE))?;
    expect("the passkey still logs in", crisis.starts_with("ok "), &crisis)?;
    let glass_token = crisis.strip_prefix("ok ").ok_or("no token")?.to_owned();
    let used = ask(&mut tool, &format!("breakglass-status {admin}"))?;
    expect(
        "the last use is now shown",
        !used.contains("never") && used.starts_with("glass 1 "),
        &used,
    )?;
    let by_manager = ask(&mut tool, &format!("wa-register-start {admin} glass"))?;
    expect("a manager cannot register a passkey for it", by_manager.starts_with("error"), &by_manager)?;
    let by_self = ask(&mut tool, &format!("roles {admin} admin administrator,glass"))?;
    expect("nobody grants themselves the role", by_self.starts_with("error"), &by_self)?;
    let last = ask(&mut tool, &format!("wa-remove {glass_token} glass {credential}"))?;
    expect("the last passkey cannot be removed", last.starts_with("error"), &last)?;
    finish(tool)
}


fn read_back(rig: &Rig) -> Result<(), Box<dyn Error>> {
    let audit = fs::read_to_string(file_in(rig, "audit.log"))?;
    say("--- audit records of the glass account ---")?;
    audit.lines().filter(|line| line.contains("glass")).try_for_each(|line| say(line))?;
    let marked = audit.lines().filter(|line| line.contains("\"break_glass\":\"true\"")).count();
    expect("records carry the marker", marked > 0, &marked.to_string())?;
    expect("a grant is marked", audit.contains("\"break_glass_change\":\"grant\""), "audit.log")?;
    expect(
        "no password reaches the audit",
        !audit.contains(PASSWORD) && !audit.contains("wrong-password"),
        "audit.log",
    )?;
    expect(
        "the status read is audited with a count",
        audit.contains("auth.breakglass.status"),
        "audit.log",
    )
}


fn run(binary: &str, directory: &str, rp_id: &str, origin: &str) -> Result<(), Box<dyn Error>> {
    let rig = Rig {
        binary: binary.to_owned(),
        directory: directory.to_owned(),
        origin: Url::parse(origin)?,
    };
    prepare(&rig, rp_id)?;
    let mut soft = SoftPasskey::new(true);
    scenario(&rig, &mut soft)?;
    read_back(&rig)
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [binary, directory, rp_id, origin] => run(binary, directory, rp_id, origin),
        _ => Err("usage: breakglass_proof <ostyr-auth> <directory> <rp id> <origin>".into()),
    }
}
