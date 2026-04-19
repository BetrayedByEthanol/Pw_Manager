use std::error::Error;
use std::io;
use std::io::Write;
use crossterm::{cursor, event::{self, Event, KeyCode}, execute, queue, terminal, terminal::{disable_raw_mode, enable_raw_mode}};
use crossterm::event::{read, KeyEvent};
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor, Stylize};
use crossterm::terminal::ClearType;
use crate::vault::entry::{EntryType, VaultyEntry};
use crate::vault::payload::PasswordEntry;
use crate::vault::Vault;
use dialoguer::{Select, Input};

mod commands;
mod ui;
mod args;


pub fn prompt_yes_no(question: &str) -> Result<bool, Box<dyn Error>> {
    print!("{} (y/n)", question);

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
    let answer = input.trim().to_string();
    println!();
    io::stdout().flush()?;

    Ok(answer)
}

pub fn menu(vault : &Vault) -> Result<(), Box<dyn Error>> {
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
        "stop server"
    ];

    let mut stdout = io::stdout();

    let mut selected = 0usize;
    let len = items.len();

    enable_raw_mode()?;
    let prompt = "Choose your target";
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

        for (i, item) in items.iter().enumerate() {
            if i == selected {
                queue!(
                    stdout,
                    SetForegroundColor(Color::Cyan),
                    Print("> "),
                    SetForegroundColor(Color::Yellow),
                    Print(format!("{}. {}", i + 1, item)),
                    ResetColor,
                    Print("\r\n"),
                )?;
            } else {
                queue!(
                    stdout,
                    Print("  "),
                    SetForegroundColor(Color::DarkGrey),
                    Print(format!("{}. {}", i + 1, item)),
                    ResetColor,
                    Print("\r\n"),
                )?;
            }
        }

        let lines = (len + 1) as u16;
        queue!(stdout, cursor::MoveUp(lines))?;

        stdout.flush()
    };

    render(&mut stdout, selected)?;

    loop {
        if let Event::Key(KeyEvent { code, .. }) = event::read()? {
            match code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if selected > 0 {
                        selected -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if selected < len - 1 {
                        selected += 1;
                    }
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let n = c as usize - '0' as usize;
                    if n >= 1 && n <= len {
                        selected = n - 1;
                        break;
                    }
                }
                KeyCode::Enter => break,
                KeyCode::Esc | KeyCode::Char('q') => {
                    let lines = (len + 1) as u16;
                    execute!(
                        stdout,
                        cursor::MoveDown(lines),
                        cursor::Show,
                        ResetColor,
                    )?;
                    disable_raw_mode()?;
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled").into());
                }
                _ => {}
            }

            render(&mut stdout, selected)?;
        }
    }

    let lines = (len + 1) as u16;
    execute!(
        stdout,
        cursor::MoveDown(lines),
        cursor::Show,
    )?;

    disable_raw_mode()?;

    // println!(
    //     "{} {}  {}. {}",
    //     "✔".green(),
    //     prompt,
    //     selected + 1,
    //     items[selected].yellow(),
    // );

    handle_selection(selected, vault)?;

    Ok(())
}

fn handle_selection(selection: usize, vault : &Vault) -> Result<(), Box<dyn Error>> {
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

        _ => println!("Invalid selection"),
    }

    Ok(())
}

fn stop_server(vault : &Vault) -> Result<(), Box<dyn Error>> {
    Ok(())

}

fn start_server(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    Ok(())
}

fn update_master(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    Ok(())
}

fn remove_device(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    Ok(())
}

fn remove_entry(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    Ok(())
}

fn show_entry(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    let entry = find_entry(vault)?;
    let payload = entry.decrypt_entry_payload(vault.header.metadata.vault_id, &vault.header.kdf, &vault.derived.vault_secret)?;
    let cast_entry = payload.as_any().downcast_ref::<PasswordEntry>().ok_or("Failed to downcast entry")?;
    println!("{:}", cast_entry);
    Ok(())
}

fn update_entry(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    let mut entry = find_entry(vault)?.clone();
    let payload = entry.decrypt_entry_payload(vault.header.metadata.vault_id, &vault.header.kdf, &vault.derived.vault_secret)?;
    let mut cast_entry = payload.as_any().downcast_ref::<PasswordEntry>().ok_or("Failed to downcast entry")?;
    entry.domain_tag = "asdasd".to_string();

    entry.updated_at = now();
    let mut new = VaultyEntry {
        entry_length: 0,
        wrapped_key: entry.wrapped_key.clone(),
        domain_tag: "".to_string(),
        domain_tag_length: 0,
        entry_type: EntryType::Password,
        nonce: entry.nonce.clone(),
        salt: entry.salt.clone(),
        wrapping_nonce: entry.wrapping_nonce.clone(),
        version: 0,
        entry_id: Default::default(),
        payload: vec![],
        payload_length: 0,
        target: "".to_string(),
        target_length: 0,
        is_default: false,
        created_at: 0,
        updated_at: 0,
    };
    let mut new_payload = PasswordEntry{
        title_length: 0,
        title: "".to_string(),
        username_length: 0,
        username: None,
        password_length: 0,
        password: Default::default(),
        url_count: 0,
        urls: vec![],
        notes_length: 0,
        notes: None,
    };

    loop {
        let options = vec!["Title", "Username", "Password", "URLs", "Notes", "Done"];

        // extra pw        //entry pw
        // title          // Amazon
        // username
        // password
        // urls ?         // allowed urls -> amazon.de/login
        // notes
        // target        // target domain -> amazon.de
        // domain_tag    // amazon ... title.lower

        let choice = Select::new()
            .with_prompt("Edit field")
            .items(&options)
            .default(0)
            .interact()?;

        match options[choice] {
            "Title" => {
                new_payload.title = Input::new()
                    .with_prompt("New title")
                    .with_initial_text(&cast_entry.title)
                    .interact_text()?;
            }
            // "Username" => {
            //     let input: String = Input::new()
            //         .with_prompt("Username (empty = None)")
            //         .allow_empty(true)
            //         .interact_text()?;
            //
            //     entry.username = if input.is_empty() { None } else { Some(input) };
            // }
            // "URLs" => {
            //     let input: String = Input::new()
            //         .with_prompt("Comma-separated URLs")
            //         .with_initial_text(entry.urls.join(","))
            //         .interact_text()?;
            //
            //     entry.urls = input
            //         .split(',')
            //         .map(|s| s.trim().to_string())
            //         .filter(|s| !s.is_empty())
            //         .collect();
            // }
            // "Notes" => {
            //     let input: String = Input::new()
            //         .with_prompt("Notes (empty = None)")
            //         .allow_empty(true)
            //         .interact_text()?;
            //
            //     entry.notes = if input.is_empty() { None } else { Some(input) };
            // }
            "Done" => break,
            _ => {}
        }
    }

    Ok(())
}

fn add_entry(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    Ok(())
}

fn load_entry(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    let entry = find_entry(vault)?;
    let payload = entry.decrypt_entry_payload(vault.header.metadata.vault_id, &vault.header.kdf, &vault.derived.vault_secret)?;
    let cast_entry = payload.as_any().downcast_ref::<PasswordEntry>().ok_or("Failed to downcast entry")?;
    Ok(())
}

fn find_entry(vault: &Vault) -> Result<&VaultyEntry, Box<dyn Error>> {
    let entry_id = prompt_question("Enter entry name: ")?;

    let entry = vault.body.entries.iter().find(|&e| e.domain_tag == entry_id).ok_or("Entry not found")?;
    Ok(entry)
}

fn list_devices(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    for device in vault.body.authorized_clients.iter() {
        println!("{:?}", device);
    }
    Ok(())
}

fn list_entries(vault : &Vault) ->  Result<(), Box<dyn Error>>  {
    println!("list entries");
    for entry in vault.body.entries.iter() {
        println!("{:?}", entry.domain_tag);
    }
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}