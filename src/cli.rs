use std::env;
use std::error::Error;
use std::io::{self, Write};

use crossterm::{
    cursor,
    event::{self, read, Event, KeyCode, KeyEvent},
    execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, disable_raw_mode, enable_raw_mode, ClearType},
};
use dialoguer::{Input, MultiSelect, Select};
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};

use crate::fsutil::atomic_write;
use crate::util::pw_generator::{generate_password, CharSet};
use crate::vault::payload::PasswordEntry;
use crate::vault::Vault;

mod args;
mod commands;
mod ui;

pub fn prompt_yes_no(question: &str) -> Result<bool, Box<dyn Error>> {
    print!("{} (y/n) ", question);
    io::stdout().flush()?;

    enable_raw_mode()?;

    let result = loop {
        if let Event::Key(event) = read()? {
            match event.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => break true,
                KeyCode::Char('n') | KeyCode::Char('N') => break false,
                _ => {}
            }
        }
    };

    disable_raw_mode()?;
    println!();

    Ok(result)
}

pub fn prompt_question(question: &str) -> Result<String, Box<dyn Error>> {
    print!("{}", question);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    println!();
    io::stdout().flush()?;

    Ok(input.trim().to_string())
}

pub fn prompt_pw(question: String) -> Result<SecretString, Box<dyn Error>> {
    print!("{}", question);

    let env_var = if question.to_lowercase().contains("password") {
        "MASTER_PASSWORD"
    } else {
        "PIN"
    };

    if let Ok(value) = env::var(env_var) {
        return Ok(SecretString::from(value));
    }

    io::stdout().flush()?;

    match read_password() {
        Ok(password) => Ok(SecretString::from(password)),
        Err(err) => {
            eprintln!("\n[ERROR] Secure input unavailable: {err}");
            eprintln!("[ERROR] Aborting — refusing to prompt with echo enabled.");
            Err(err.into())
        }
    }
}

/// Prompts for an optional entry-specific password.
///
/// Returns `(password, is_default)`. If the user leaves the password empty,
/// `is_default` is true and the caller should use the vault default secret.
pub fn prompt_entry_pw(hint: &str) -> Result<(SecretString, bool), Box<dyn Error>> {
    print!("{} (leave empty to use default vault secret): ", hint);
    io::stdout().flush()?;

    let raw = read_password().map_err(|err| {
        eprintln!("\n[ERROR] Secure input unavailable: {err}");
        err
    })?;

    let is_default = raw.trim().is_empty();
    Ok((SecretString::from(raw), is_default))
}

fn parse_semicolon_list(input: &str) -> Vec<String> {
    input
        .split(';')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn prompt_charset() -> Result<CharSet, Box<dyn Error>> {
    let options = vec![
        "Uppercase (A-Z)",
        "Lowercase (a-z)",
        "Digits (0-9)",
        "Special (!@#$...)",
    ];

    let selected = MultiSelect::new()
        .with_prompt("Character sets")
        .items(&options)
        .defaults(&[true, true, true, false])
        .interact()?;

    if selected.is_empty() {
        eprintln!("[WARN] No charset selected, defaulting to all.");
        return Ok(CharSet::ALL);
    }

    let mut charset = CharSet(0);
    for index in selected {
        charset = match index {
            0 => charset | CharSet::UPPERCASE,
            1 => charset | CharSet::LOWERCASE,
            2 => charset | CharSet::DIGITS,
            3 => charset | CharSet::SPECIAL,
            _ => charset,
        };
    }

    Ok(charset)
}

pub fn menu(vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    let items = vec![
        "list entries",
        "list devices",
        "load entry",
        "add entry",
        "update entry",
        "show entry",
        "remove entry",
        "remove device",
        "update master",
        "start server",
        "stop server",
        "add fido2 device",
        "remove fido2 device",
    ];

    let mut stdout = io::stdout();
    let mut selected = 0usize;
    let len = items.len();
    let prompt = "Choose your target";

    enable_raw_mode()?;
    execute!(stdout, cursor::Hide)?;

    let render = |stdout: &mut io::Stdout, selected: usize| -> io::Result<()> {
        queue!(stdout, terminal::Clear(ClearType::FromCursorDown))?;
        queue!(
            stdout,
            SetForegroundColor(Color::Green),
            Print("? "),
            ResetColor,
            Print(prompt),
            Print("\r\n"),
        )?;

        for (index, item) in items.iter().enumerate() {
            if index == selected {
                queue!(
                    stdout,
                    SetForegroundColor(Color::Cyan),
                    Print("> "),
                    SetForegroundColor(Color::Yellow),
                    Print(format!("{}. {}", index + 1, item)),
                    ResetColor,
                    Print("\r\n"),
                )?;
            } else {
                queue!(
                    stdout,
                    Print("  "),
                    SetForegroundColor(Color::DarkGrey),
                    Print(format!("{}. {}", index + 1, item)),
                    ResetColor,
                    Print("\r\n"),
                )?;
            }
        }

        queue!(stdout, cursor::MoveUp((len + 1) as u16))?;
        stdout.flush()
    };

    render(&mut stdout, selected)?;

    loop {
        if let Event::Key(KeyEvent { code, .. }) = event::read()? {
            match code {
                KeyCode::Up | KeyCode::Char('k') => {
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if selected < len - 1 {
                        selected += 1;
                    }
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let n = c as usize - '0' as usize;
                    if (1..=len).contains(&n) {
                        selected = n - 1;
                        break;
                    }
                }
                KeyCode::Enter => break,
                KeyCode::Esc | KeyCode::Char('q') => {
                    execute!(stdout, cursor::MoveDown((len + 1) as u16), cursor::Show, ResetColor)?;
                    disable_raw_mode()?;
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled").into());
                }
                _ => {}
            }

            render(&mut stdout, selected)?;
        }
    }

    execute!(stdout, cursor::MoveDown((len + 1) as u16), cursor::Show, ResetColor)?;
    disable_raw_mode()?;

    handle_selection(selected, vault)
}

fn handle_selection(selection: usize, vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    match selection {
        0 => list_entries(vault)?,
        1 => list_devices(vault)?,
        2 => load_entry(vault)?,
        3 => add_entry(vault)?,
        4 => update_entry(vault)?,
        5 => show_entry(vault)?,
        6 => remove_entry(vault)?,
        7 => remove_device(vault)?,
        8 => update_master(vault)?,
        9 => start_server(vault)?,
        10 => stop_server(vault)?,
        11 => add_fido2_device(vault)?,
        12 => remove_fido2_device(vault)?,
        _ => println!("Invalid selection"),
    }

    Ok(())
}

// ── Stubs ────────────────────────────────────────────────────────────────────

fn stop_server(_vault: &Vault) -> Result<(), Box<dyn Error>> {
    println!("[WIP] stop server not yet implemented.");
    Ok(())
}

fn start_server(_vault: &Vault) -> Result<(), Box<dyn Error>> {
    println!("[WIP] start server not yet implemented.");
    Ok(())
}

fn add_fido2_device(_vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    println!("[WIP] FIDO2 device registration not yet implemented.");
    Ok(())
}

fn remove_fido2_device(_vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    println!("[WIP] FIDO2 device removal not yet implemented.");
    Ok(())
}

fn remove_device(_vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    println!("[WIP] device/client management not yet implemented.");
    Ok(())
}

fn list_devices(vault: &Vault) -> Result<(), Box<dyn Error>> {
    if vault.body.authorized_clients.is_empty() {
        println!("No authorized clients.");
        return Ok(());
    }

    println!("Authorized clients:");
    for (index, device) in vault.body.authorized_clients.iter().enumerate() {
        println!("  {}. {:?}", index + 1, device);
    }

    Ok(())
}

// ── Entry helpers ─────────────────────────────────────────────────────────────

fn pick_entry(vault: &Vault) -> Result<usize, Box<dyn Error>> {
    if vault.body.entries.is_empty() {
        return Err("No entries in vault.".into());
    }

    let labels: Vec<String> = vault
        .body
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| format!("{}. {} ({})", index + 1, entry.domain_tag, entry.entry_id))
        .collect();

    let choice = Select::new()
        .with_prompt("Select entry")
        .items(&labels)
        .default(0)
        .interact()?;

    Ok(choice)
}

fn list_entries(vault: &Vault) -> Result<(), Box<dyn Error>> {
    if vault.body.entries.is_empty() {
        println!("No entries.");
        return Ok(());
    }

    println!("{:<4} {:<24} {:<36} {}", "#", "Tag", "ID", "Default key");
    println!("{}", "-".repeat(72));

    for (index, entry) in vault.body.entries.iter().enumerate() {
        println!(
            "{:<4} {:<24} {:<36} {}",
            index + 1,
            entry.domain_tag,
            entry.entry_id,
            if entry.is_default { "yes" } else { "no" }
        );
    }

    Ok(())
}

fn show_entry(vault: &Vault) -> Result<(), Box<dyn Error>> {
    let index = pick_entry(vault)?;
    let entry = &vault.body.entries[index];
    let payload = entry.decrypt_entry_payload(
        vault.header.metadata.vault_id,
        &vault.header.kdf,
        &vault.derived.vault_secret,
    )?;

    let password_entry = payload
        .as_any()
        .downcast_ref::<PasswordEntry>()
        .ok_or("Failed to downcast entry")?;

    println!("{}", password_entry);
    Ok(())
}

fn load_entry(vault: &Vault) -> Result<(), Box<dyn Error>> {
    let index = pick_entry(vault)?;
    let entry = &vault.body.entries[index];
    let payload = entry.decrypt_entry_payload(
        vault.header.metadata.vault_id,
        &vault.header.kdf,
        &vault.derived.vault_secret,
    )?;

    let password_entry = payload
        .as_any()
        .downcast_ref::<PasswordEntry>()
        .ok_or("Failed to downcast entry")?;

    println!("Loaded: {} ({})", password_entry.title, entry.domain_tag);
    Ok(())
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

fn add_entry(vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    let title: String = Input::new().with_prompt("Title").interact_text()?;

    let username_raw: String = Input::new()
        .with_prompt("Username / email (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let username = match username_raw.trim() {
        "" => None,
        _ => Some(username_raw),
    };

    let generate = prompt_yes_no("Generate password?")?;
    let (password, is_default) = if generate {
        let charset = prompt_charset()?;
        let length_raw: String = Input::new()
            .with_prompt("Password length")
            .default("20".to_string())
            .interact_text()?;
        let length = length_raw.trim().parse().unwrap_or(20);
        (generate_password(charset, length)?, true)
    } else {
        prompt_entry_pw("Entry password")?
    };

    let target: String = Input::new()
        .with_prompt("Target domain (e.g. amazon.de)")
        .interact_text()?;

    let domain_tag: String = Input::new()
        .with_prompt("Tag / slug (e.g. amazon)")
        .with_initial_text(&title.to_lowercase().replace(' ', "-"))
        .interact_text()?;

    let uris_raw: String = Input::new()
        .with_prompt("Allowed URIs, semicolon-separated (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let allowed_uris = parse_semicolon_list(&uris_raw);

    let notes_raw: String = Input::new()
        .with_prompt("Notes (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let notes = match notes_raw.trim() {
        "" => None,
        _ => Some(notes_raw),
    };

    vault.add_entry(
        is_default,
        domain_tag,
        target,
        title,
        username,
        password,
        allowed_uris,
        notes,
    )?;

    save_vault(vault)?;
    println!("Entry added.");
    Ok(())
}

fn update_entry(vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    let index = pick_entry(vault)?;
    let entry = &vault.body.entries[index];
    let payload = entry.decrypt_entry_payload(
        vault.header.metadata.vault_id,
        &vault.header.kdf,
        &vault.derived.vault_secret,
    )?;

    let current = payload
        .as_any()
        .downcast_ref::<PasswordEntry>()
        .ok_or("Failed to downcast entry")?;

    let mut new_title = current.title.clone();
    let mut new_username = current.username.clone();
    let mut new_password: Option<SecretString> = None;
    let mut new_is_default = vault.body.entries[index].is_default;
    let mut new_urls = current.urls.clone();
    let mut new_notes = current.notes.clone();
    let mut new_target = vault.body.entries[index].target.clone();
    let mut new_domain_tag = vault.body.entries[index].domain_tag.clone();

    loop {
        let options = vec![
            "Title",
            "Username",
            "Password",
            "Target domain",
            "Tag / slug",
            "Allowed URIs",
            "Notes",
            "Done",
        ];

        let choice = Select::new()
            .with_prompt("Edit field")
            .items(&options)
            .default(0)
            .interact()?;

        match options[choice] {
            "Title" => {
                new_title = Input::new()
                    .with_prompt("Title")
                    .with_initial_text(&new_title)
                    .interact_text()?;
            }
            "Username" => {
                let raw: String = Input::new()
                    .with_prompt("Username / email (leave empty to clear)")
                    .with_initial_text(new_username.as_deref().unwrap_or(""))
                    .allow_empty(true)
                    .interact_text()?;
                new_username = match raw.trim() {
                    "" => None,
                    _ => Some(raw),
                };
            }
            "Password" => {
                let (password, is_default) = prompt_entry_pw("New entry password")?;
                new_password = Some(password);
                new_is_default = is_default;
            }
            "Target domain" => {
                new_target = Input::new()
                    .with_prompt("Target domain (e.g. amazon.de)")
                    .with_initial_text(&new_target)
                    .interact_text()?;
            }
            "Tag / slug" => {
                new_domain_tag = Input::new()
                    .with_prompt("Tag / slug")
                    .with_initial_text(&new_domain_tag)
                    .interact_text()?;
            }
            "Allowed URIs" => {
                let raw: String = Input::new()
                    .with_prompt("Allowed URIs, semicolon-separated (leave empty to clear)")
                    .with_initial_text(&new_urls.join(";"))
                    .allow_empty(true)
                    .interact_text()?;
                new_urls = parse_semicolon_list(&raw);
            }
            "Notes" => {
                let raw: String = Input::new()
                    .with_prompt("Notes (leave empty to clear)")
                    .with_initial_text(new_notes.as_deref().unwrap_or(""))
                    .allow_empty(true)
                    .interact_text()?;
                new_notes = match raw.trim() {
                    "" => None,
                    _ => Some(raw),
                };
            }
            "Done" => break,
            _ => {}
        }
    }

    vault.update_entry(
        index,
        new_is_default,
        new_domain_tag,
        new_target,
        new_title,
        new_username,
        new_password,
        new_urls,
        new_notes,
    )?;

    save_vault(vault)?;
    println!("Entry updated.");
    Ok(())
}

fn remove_entry(vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    let index = pick_entry(vault)?;
    let tag = vault.body.entries[index].domain_tag.clone();

    if !prompt_yes_no(&format!("Remove entry \"{}\"?", tag))? {
        println!("Aborted.");
        return Ok(());
    }

    vault.body.entries.remove(index);
    save_vault(vault)?;

    println!("Entry \"{}\" removed.", tag);
    Ok(())
}

fn update_master(vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    let current = prompt_pw("Current master password: ".to_string())?;
    let new_password = prompt_pw("New master password: ".to_string())?;
    let confirm = prompt_pw("Confirm new master password: ".to_string())?;

    if new_password.expose_secret() != confirm.expose_secret() {
        return Err("Passwords do not match.".into());
    }

    vault.change_master(current, new_password)?;
    save_vault(vault)?;

    println!("Master password updated.");
    Ok(())
}

fn save_vault(vault: &mut Vault) -> Result<(), Box<dyn Error>> {
    let sealed_vault = vault.seal_vault()?;
    atomic_write(&sealed_vault.serialize()?)?;
    Ok(())
}
