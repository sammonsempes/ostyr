//! Live proof driver: runs `auth_tool` with a software passkey; usage `soft_proof <auth_tool> <directory> <rp id> <origin>`.

use data_encoding::BASE64URL_NOPAD;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::io::{stdout, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use webauthn_authenticator_rs::prelude::{Url, WebauthnAuthenticator};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;


const PASSWORD: &str = "correct-horse-battery";


const SOURCE: &str = "10.0.0.7";


const REPLY_PARTS: usize = 3;


const KEY_BYTES: usize = 32;


const KEY_FILL: u8 = 9;


const OWNER_ONLY: u32 = 0o600;


const HIGH_COUNTER: u64 = 1000;


const UUID_BYTES: usize = 16;


const USER_HANDLE_DOMAIN: &str = "ostyr-webauthn-user:";


const ROLES: &str = r#"[{"name":"breakglass","permissions":["users.manage","policy.webauthn_required"]}]"#;


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


fn private_file(path: &Path, content: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
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
    let reply = ask(
        tool,
        &format!(
            "wa-register-finish {token} {user} {challenge} soft-key {}",
            serde_json::to_string(&response)?
        ),
    )?;
    Ok(reply.strip_prefix("ok ").ok_or("registration refused")?.to_owned())
}


fn passkey_assertion(rig: &Rig, tool: &mut Tool, soft: &mut SoftPasskey, (credential, user): (&str, &str)) -> Result<String, Box<dyn Error>> {
    let (challenge, options) = split_reply(&ask(tool, &format!("passkey-start {SOURCE}"))?)?;
    let mut request: Value = serde_json::from_str(&options)?;
    set_at(
        &mut request,
        "/publicKey/allowCredentials",
        json!([{ "type": "public-key", "id": credential }]),
    )?;
    let mut response = serde_json::to_value(soft.do_authentication(rig.origin.clone(), serde_json::from_value(request)?)?)?;
    set_at(&mut response, "/response/userHandle", json!(user_handle(user)))?;
    Ok(format!("wa-login-finish {challenge} {SOURCE} {response}"))
}


fn totp_code(tool: &mut Tool, secret: &str) -> Result<String, Box<dyn Error>> {
    ask(tool, &format!("totp {secret}"))
}


fn setup(rig: &Rig, soft: &mut SoftPasskey) -> Result<String, Box<dyn Error>> {
    let mut tool = spawn(rig)?;
    writeln!(tool.input, "bootstrap admin {PASSWORD}")?;
    let secret_line = read_reply(&mut tool)?;
    read_reply(&mut tool)?;
    let secret = secret_line.strip_prefix("secret ").ok_or("no secret")?.to_owned();
    let code = totp_code(&mut tool, &secret)?;
    let logged = ask(&mut tool, &format!("login admin {PASSWORD} {SOURCE} {code}"))?;
    let token = logged.strip_prefix("ok ").ok_or("admin login refused")?.to_owned();
    let created = ask(&mut tool, &format!("create {token} glass {PASSWORD} breakglass"))?;
    expect("break-glass account created", created == "ok", &created)?;
    let credential = register(rig, &mut tool, soft, (&token, "admin"))?;
    expect("passkey registered for the administrator", !credential.is_empty(), &credential)?;
    let enrolled = ask(&mut tool, &format!("enrol {token} glass"))?;
    read_reply(&mut tool)?;
    let glass_secret = enrolled.strip_prefix("secret ").ok_or("no glass secret")?.to_owned();
    finish(tool)?;
    say(&format!("credential {credential}"))?;
    Ok(format!("{credential} {glass_secret}"))
}


fn passwordless(rig: &Rig, soft: &mut SoftPasskey, credential: &str) -> Result<(), Box<dyn Error>> {
    let mut tool = spawn(rig)?;
    let finish_line = passkey_assertion(rig, &mut tool, soft, (credential, "admin"))?;
    let logged = ask(&mut tool, &finish_line)?;
    expect("passwordless login", logged.starts_with("ok "), &logged)?;
    let token = logged.strip_prefix("ok ").ok_or("no token")?;
    let checked = ask(&mut tool, &format!("check {token}"))?;
    expect("the passkey session is valid", checked == "allowed admin", &checked)?;
    let replayed = ask(&mut tool, &finish_line)?;
    expect(
        "replaying the same assertion is refused",
        replayed == "error invalid credentials",
        &replayed,
    )?;
    finish(tool)
}


fn regression(rig: &Rig, soft: &mut SoftPasskey, credential: &str) -> Result<(), Box<dyn Error>> {
    let path = file_in(rig, "accounts.json");
    let mut store: Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
    set_at(&mut store, "/credentials/0/passkey/cred/counter", json!(HIGH_COUNTER))?;
    fs::write(&path, serde_json::to_string_pretty(&store)?)?;
    let mut tool = spawn(rig)?;
    let finish_line = passkey_assertion(rig, &mut tool, soft, (credential, "admin"))?;
    let refused = ask(&mut tool, &finish_line)?;
    expect(
        "an assertion below the stored counter is refused",
        refused == "error invalid credentials",
        &refused,
    )?;
    finish(tool)
}


fn required(rig: &Rig, glass_secret: &str) -> Result<(), Box<dyn Error>> {
    let mut tool = spawn(rig)?;
    let code = totp_code(&mut tool, glass_secret)?;
    let refused = ask(&mut tool, &format!("login glass {PASSWORD} {SOURCE} {code}"))?;
    expect(
        "a valid TOTP code does not satisfy webauthn_required",
        refused.contains("WebAuthn credential is required"),
        &refused,
    )?;
    finish(tool)
}


fn read_back(rig: &Rig) -> Result<(), Box<dyn Error>> {
    let store = fs::read_to_string(file_in(rig, "accounts.json"))?;
    let audit = fs::read_to_string(file_in(rig, "audit.log"))?;
    say("--- store (credentials) ---")?;
    say(&serde_json::from_str::<Value>(&store)?
        .get("credentials")
        .map_or_else(String::new, |value| value.to_string()))?;
    say("--- audit (webauthn and login records) ---")?;
    audit
        .lines()
        .filter(|line| line.contains("webauthn") || line.contains("auth.login"))
        .try_for_each(|line| say(line))?;
    expect("counter_regression is audited", audit.contains("counter_regression"), "audit.log")?;
    expect("webauthn_required is audited", audit.contains("webauthn_required"), "audit.log")
}


fn run(binary: &str, directory: &str, rp_id: &str, origin: &str) -> Result<(), Box<dyn Error>> {
    let rig = Rig {
        binary: binary.to_owned(),
        directory: directory.to_owned(),
        origin: Url::parse(origin)?,
    };
    prepare(&rig, rp_id)?;
    let mut soft = SoftPasskey::new(true);
    let both = setup(&rig, &mut soft)?;
    let (credential, glass_secret) = both.split_once(' ').ok_or("setup reply")?;
    passwordless(&rig, &mut soft, credential)?;
    regression(&rig, &mut soft, credential)?;
    required(&rig, glass_secret)?;
    read_back(&rig)
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [binary, directory, rp_id, origin] => run(binary, directory, rp_id, origin),
        _ => Err("usage: soft_proof <auth_tool> <directory> <rp id> <origin>".into()),
    }
}
