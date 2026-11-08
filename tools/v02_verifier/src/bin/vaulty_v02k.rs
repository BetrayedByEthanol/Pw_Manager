//! V02-K local physical FIDO2 evidence runner (NOT a Vaulty authenticator).
//! Calls the existing V02-J operator-only Python/libfido2 harness. Rust never
//! receives hardware PRF bytes, PINs, credential IDs, or a Vaulty key.
//! A local operator observation is NOT external OPEN-15/OPEN-01 approval.
#![forbid(unsafe_code)]
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, &'static str>;
const SCHEMA: &str = "vaulty-v02k-redacted-evidence-v1";
const KEYS: [&str; 13] = [
    "schema", "review_only", "device_execution", "full_i_p01_to_i_p09_matrix",
    "operation", "signature_and_requested_flags_checked", "assurance_requested",
    "uv_absence_verified", "repeat_prf_stable", "different_entry_prf_distinct",
    "entry_route_ready", "open_15_approved", "open_01_approved",
];
const HELP: &str = "
V02-K Linux physical FIDO2 test (review-only; no real vault data).
Requires Python 3, fido2-tools, Rust, and two test authenticator credentials.

cargo run --locked --manifest-path tools/v02_verifier/Cargo.toml --bin vaulty_v02k -- preflight

cargo run --locked --manifest-path tools/v02_verifier/Cargo.toml --bin vaulty_v02k -- run --primary-device /dev/hidrawX --backup-device /dev/hidrawY --rp-id vaulty-review.localhost --hardware-test

Find device paths with: fido2-token -L
If the backup is swapped into the same path, enter that same path twice.
Only share evidence-v02k.json; NEVER share the private session/receipt files.
";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation { stable: bool, isolated: bool }
#[derive(Clone, Debug)]
struct Options { mode: String, primary: Option<String>, backup: Option<String>,
                 rp: String, live: bool }

fn options(mut a: impl Iterator<Item=String>) -> Result<Options> {
    let mode = a.next().unwrap_or_else(|| "help".into());
    if !matches!(mode.as_str(), "help"|"--help"|"preflight"|"run") {
        return Err("expected preflight or run");
    }
    let mut o = Options { mode, primary: None, backup: None,
                          rp: "vaulty-review.localhost".into(), live: false };
    let mut seen = BTreeSet::new();
    while let Some(k) = a.next() {
        if !seen.insert(k.clone()) { return Err("duplicated CLI option"); }
        match k.as_str() {
            "--hardware-test" => o.live = true,
            "--primary-device" => o.primary = Some(a.next().ok_or("missing device")?),
            "--backup-device" => o.backup = Some(a.next().ok_or("missing device")?),
            "--rp-id" => o.rp = a.next().ok_or("missing RP ID")?,
            _ => return Err("unknown CLI option"),
        }
    }
    if o.mode == "run" && (!o.live || o.primary.is_none() || o.backup.is_none()) {
        return Err("run needs --hardware-test and both device paths");
    }
    if o.mode != "run" && (o.live || o.primary.is_some() || o.backup.is_some()) {
        return Err("hardware flags only permitted for run");
    }
    if !valid_rp(&o.rp) { return Err("use a lowercase synthetic RP ID"); }
    Ok(o)
}
fn valid_rp(s: &str) -> bool {
    s.len() <= 253 && s.len() >= 4 && s.contains('.') && !s.contains("..")
        && !s.starts_with('-') && !s.starts_with('.')
        && !s.ends_with('-') && !s.ends_with('.')
        && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()
                          || c == b'.' || c == b'-')
}
fn device(path: &str) -> Result<()> {
    let digits = path.strip_prefix("/dev/hidraw").ok_or("expected /dev/hidrawN")?;
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err("expected /dev/hidrawN");
    }
    let m = fs::symlink_metadata(path).map_err(|_| "device missing or unplugged")?;
    if m.file_type().is_symlink() || !m.file_type().is_char_device() {
        return Err("device is not a direct HID character device");
    }
    Ok(())
}
fn live_gate() -> Result<()> {
    if !cfg!(target_os="linux") { return Err("Linux hardware test only"); }
    if ["CI","GITHUB_ACTIONS","FORGEJO_ACTIONS"].iter()
        .any(|k| env::var(k).is_ok_and(|v| !v.is_empty())) {
        return Err("refusing physical operations in CI");
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("interactive terminal required for device/PIN prompts");
    }
    if env::var("USER").is_ok_and(|v| v=="root") {
        return Err("do not run the test under sudo/root");
    }
    Ok(())
}
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}
fn harness() -> Result<PathBuf> {
    let p=root().join("tools/hardware/fido2_v02j.py");
    if !p.is_file() || p.is_symlink() { return Err("missing/linked V02-J harness"); }
    Ok(p)
}
fn pinned_head() -> Result<String> {
    let dir=root();
    let out=Command::new("git").arg("-C").arg(&dir).args(["rev-parse","HEAD"])
        .stderr(Stdio::null()).output().map_err(|_|"git is required")?;
    let sha=String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if !out.status.success() || sha.len()!=40 ||
       !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid Git source revision");
    }
    let changes=Command::new("git").arg("-C").arg(&dir).args(["status","--porcelain"])
        .stderr(Stdio::null()).output().map_err(|_|"git status unavailable")?;
    if !changes.status.success() || !changes.stdout.is_empty() {
        return Err("checkout must be clean for pinned hardware evidence");
    }
    Ok(sha)
}
fn make_private_dir(path: &Path) -> Result<()> {
    let mut ancestor=Some(path);
    while let Some(p)=ancestor {
        if p.is_symlink() { return Err("symlinked output path refused"); }
        ancestor=p.parent();
    }
    if path.exists() {
        let m=fs::symlink_metadata(path).map_err(|_|"unreadable output dir")?;
        if !m.is_dir() || m.permissions().mode() & 0o077 != 0 {
            return Err("output directory is not private mode 0700");
        }
    } else {
        DirBuilder::new().mode(0o700).create(path).map_err(|_|"cannot create private directory")?;
    }
    Ok(())
}
fn ensure_ancestor_dir(path: &Path) -> Result<()> {
    if path.is_symlink() { return Err("symlinked output ancestor"); }
    if !path.exists() {
        DirBuilder::new().mode(0o700).create(path)
            .map_err(|_|"cannot create output parent")?;
    }
    let m=fs::symlink_metadata(path).map_err(|_|"cannot inspect output parent")?;
    if !m.is_dir() || m.permissions().mode() & 0o022 != 0 {
        return Err("writable or non-directory output parent");
    }
    Ok(())
}
fn new_output() -> Result<PathBuf> {
    let home=PathBuf::from(env::var_os("HOME").ok_or("missing HOME")?);
    if !home.is_absolute() || !home.is_dir() || home.is_symlink() {
        return Err("invalid HOME");
    }
    let local=home.join(".local"); let state=local.join("state");
    let base=state.join("vaulty-v02k");
    // Existing ~/.local and ~/.local/state are often mode 0755 and need not
    // be changed. The evidence directory itself must be mode 0700.
    for p in [&local,&state] { ensure_ancestor_dir(p)?; }
    make_private_dir(&base)?;
    let millis=SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_|"invalid local clock")?.as_millis();
    let dest=base.join(format!("run-{millis}-{}",std::process::id()));
    make_private_dir(&dest)?;
    Ok(dest)
}
fn python(tool: &Path, args: &[&str]) -> Result<()> {
    let exit=Command::new("python3").arg("-I").arg(tool).args(args)
        .status().map_err(|_|"python3 unavailable")?;
    if exit.success() { Ok(()) }
    else { Err("local FIDO2 command failed; this stage has no accepted result") }
}
fn confirm(which: &str, hid: &str) -> Result<()> {
    println!("\nConnect the {which} TEST key at {hid}.");
    println!("If you unplugged/replugged it, check again with: fido2-token -L");
    print!("Type {} to authorize the test operations: ",which.to_ascii_uppercase());
    io::stdout().flush().map_err(|_|"terminal unavailable")?;
    let mut reply=String::new();
    io::stdin().read_line(&mut reply).map_err(|_|"operator confirmation missing")?;
    if reply.trim()!=which.to_ascii_uppercase() { return Err("operator declined test"); }
    device(hid)?;
    Ok(())
}

// Strictly parse the flat, canonical, synthetic V02-J receipt. Unknown keys,
// duplicates, unexpected values or altered security gates fail closed.
// This is evidence validation, NOT signature/attestation verification.
fn fields(text: &str) -> Result<BTreeMap<String,String>> {
    if text.len()>4096 || text.contains('\0') { return Err("oversized receipt"); }
    let mut rows=text.lines().map(str::trim);
    if rows.next()!=Some("{") { return Err("unexpected receipt format"); }
    let mut map=BTreeMap::new(); let mut end=false;
    for line in rows {
        if line=="}" { if end {return Err("duplicate JSON end");} end=true; continue; }
        if end || line.is_empty() { return Err("trailing or blank receipt"); }
        let data=line.strip_suffix(',').unwrap_or(line);
        let (k,v)=data.split_once(": ").ok_or("malformed receipt entry")?;
        let k=k.strip_prefix('"').and_then(|s|s.strip_suffix('"'))
            .ok_or("malformed receipt key")?;
        if !KEYS.contains(&k) || !k.bytes().all(|c| c.is_ascii_lowercase()
            || c.is_ascii_digit() || c==b'_') { return Err("unknown receipt key"); }
        if !matches!(v,"true"|"false"|"null"|"\"vaulty-v02j-observation-v1\""
            |"\"OBSERVED\""|"\"NOT_EXECUTED\""|
            "\"signed_native_ctap_test_assertions\""|"\"uv\"") {
            return Err("unexpected receipt value");
        }
        if map.insert(k.to_owned(),v.to_owned()).is_some() {return Err("duplicate receipt key");}
    }
    if !end || map.len()!=KEYS.len() {return Err("missing receipt field");}
    Ok(map)
}
fn observation(json: &str) -> Result<Observation> {
    let v=fields(json)?;
    for (key,expected) in [
        ("schema","\"vaulty-v02j-observation-v1\""),("review_only","true"),
        ("device_execution","\"OBSERVED\""),
        ("full_i_p01_to_i_p09_matrix","\"NOT_EXECUTED\""),
        ("operation","\"signed_native_ctap_test_assertions\""),
        ("signature_and_requested_flags_checked","true"),
        ("assurance_requested","\"uv\""),("uv_absence_verified","false"),
        ("entry_route_ready","false"),("open_15_approved","false"),
        ("open_01_approved","false")
    ] {
        if v.get(key).is_none_or(|value|value!=expected) {
            return Err("unverified or unsupported hardware evidence");
        }
    }
    let boolean=|k: &str|match v.get(k).map(String::as_str) {
        Some("true")=>Ok(true),Some("false")=>Ok(false),_=>Err("missing measured boolean")
    };
    Ok(Observation{stable:boolean("repeat_prf_stable")?,
                   isolated:boolean("different_entry_prf_distinct")?})
}
fn read_observation(path: &Path) -> Result<Observation> {
    let m=fs::symlink_metadata(path).map_err(|_|"receipt absent")?;
    if !m.is_file() || m.file_type().is_symlink() || m.permissions().mode() & 0o077 != 0
        || m.len()>4096 { return Err("unsafe receipt path/mode/length"); }
    let s=fs::read_to_string(path).map_err(|_|"cannot load local receipt")?;
    observation(&s)
}
fn observed(o:&Option<Observation>)->&'static str {
    match o {None=>"NOT_EXECUTED",Some(x) if x.stable&&x.isolated=>"OBSERVED",
             Some(_)=>"OBSERVED_MISMATCH"}
}
fn report(sha:&str, outcome:&str, p:&Option<Observation>,b:&Option<Observation>)->String {
    // All interpolated values are controlled enum labels and a 40-char Git SHA.
    let first=observed(p);let second=observed(b);
    let matrix=[
        ("I-P01",if p.is_some()&&b.is_some(){"PARTIAL"}else{"NOT_EXECUTED"}),
        ("I-P02",if p.is_some()&&b.is_some(){"PARTIAL"}else{"NOT_EXECUTED"}),
        ("I-P03",if b.is_some(){"PARTIAL"}else{"NOT_EXECUTED"}),
        ("I-P04",if p.is_some(){"PARTIAL"}else{"NOT_EXECUTED"}),
        ("I-P05","NOT_EXECUTED"),
        ("I-P06",if p.is_some(){"PARTIAL"}else{"NOT_EXECUTED"}),
        ("I-P07","NOT_EXECUTED"),("I-P08","NOT_EXECUTED"),("I-P09","NOT_EXECUTED")
    ];
    let mut s=format!(
      "{{\n  \"schema\": \"{SCHEMA}\",\n  \"source_git_commit\": \"{sha}\",\n  \"review_only\": true,\n  \"status\": \"{outcome}\",\n  \"local_self_report_only\": true,\n  \"primary\": \"{first}\",\n  \"backup\": \"{second}\",\n  \"full_i_p01_to_i_p09_matrix\": \"NOT_COMPLETE\",\n  \"matrix\": {{\n");
    for (i,(k,v)) in matrix.iter().enumerate(){
        s.push_str(&format!("    \"{k}\": \"{v}\"{}\n",
                           if i+1==matrix.len(){""}else{","}));
    }
    s.push_str("  },\n  \"webauthn_browser_tested\": false,\n");
    s.push_str("  \"attestation_chain_trusted\": false,\n");
    s.push_str("  \"entry_route_ready\": false,\n");
    s.push_str("  \"open_15\": \"BLOCKED\",\n  \"open_01\": \"BLOCKED\",\n");
    s.push_str("  \"release_gates\": \"G1-G3 BLOCKED\"\n}\n");
    s
}
fn store_report(dir:&Path,body:&str)->Result<PathBuf>{
    let path=dir.join("evidence-v02k.json");
    let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&path).map_err(|_|"cannot create private evidence")?;
    file.write_all(body.as_bytes()).map_err(|_|"cannot persist evidence")?;
    file.sync_all().map_err(|_|"cannot fsync evidence")?;
    Ok(path)
}
fn stage(tool:&Path,session:&Path,dir:&Path,role:&str,hid:&str)->Result<Observation>{
    confirm(role,hid)?;
    let sess=session.to_str().ok_or("session path not UTF-8")?;
    python(tool,&["register","--session",sess,"--role",role,
                  "--device",hid,"--hardware-test"])?;
    let receipt=dir.join(format!("{role}.json"));
    let path=receipt.to_str().ok_or("receipt path not UTF-8")?;
    python(tool,&["probe","--session",sess,"--role",role,"--entry","alpha",
                  "--compare-entry","beta","--device",hid,"--hardware-test",
                  "--assurance","uv","--receipt",path])?;
    read_observation(&receipt)
}
fn run(o:&Options)->Result<()>{
    live_gate()?;
    let primary=o.primary.as_deref().ok_or("primary device missing")?;
    let backup=o.backup.as_deref().ok_or("backup device missing")?;
    device(primary)?;
    if primary!=backup {device(backup)?;}
    let sha=pinned_head()?;let tool=harness()?;let dir=new_output()?;
    let session=dir.join("session.json");
    let session_name=session.to_str().ok_or("session path not UTF-8")?;
    println!("Review-only hardware verification. Git commit: {sha}");
    println!("Private test folder: {}",dir.display());
    let mut p=None;let mut b=None;let mut state="INCOMPLETE";
    let executed=(||->Result<()>{
        python(&tool,&["init","--session",session_name,"--rp-id",&o.rp])?;
        p=Some(stage(&tool,&session,&dir,"primary",primary)?);
        b=Some(stage(&tool,&session,&dir,"backup",backup)?);
        state=if observed(&p)=="OBSERVED" && observed(&b)=="OBSERVED" {
            "LOCAL_OBSERVATIONS_CAPTURED"
        }else{"LOCAL_MISMATCH_REQUIRES_REVIEW"};
        Ok(())
    })();
    let path=store_report(&dir,&report(&sha,state,&p,&b))?;
    println!("\nShare ONLY this redacted file: {}",path.display());
    println!("Do NOT share session.json, primary.json, backup.json, PINs or PRF values.");
    println!("OPEN-01/15 and G1–G3 remain BLOCKED.");
    executed
}
fn main(){
    let result=(||->Result<()>{
        let o=options(env::args().skip(1))?;
        match o.mode.as_str(){
            "help"|"--help"=>{print!("{HELP}");Ok(())},
            "preflight"=>{println!("V02-K preflight: no hardware action.");
                python(&harness()?,&["preflight"])},
            "run"=>run(&o),_=>Err("unknown command"),
        }
    })();
    if let Err(message)=result {
        eprintln!("V02-K: {message}\nNo security approval is implied.");
        std::process::exit(2);
    }
}
#[cfg(test)]
#[path = "vaulty_v02k_tests.rs"]
mod tests;
