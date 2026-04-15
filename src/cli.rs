use std::io::Write;
use crossterm::event::{read, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

mod commands;
mod ui;
mod args;



pub fn prompt_yes_no(question: &str) -> bool {
    print!("{} (y/n)", question);

    std::io::stdout().flush().unwrap();

    enable_raw_mode().unwrap();

    let result = loop {
        if let Event::Key(event) = read().unwrap() {
            match event.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => break true,
                KeyCode::Char('n') | KeyCode::Char('N') => break false,
                _ => {}
            }
        }
    };

    disable_raw_mode().unwrap();
    println!();
    result
}