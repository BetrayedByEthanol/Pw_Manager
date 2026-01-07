// ============================================================================
// Cargo.toml dependencies for CLI module:
// ============================================================================
/*
[dependencies]
clap = { version = "4.5", features = ["derive", "cargo"] }
dialoguer = "0.11"
console = "0.15"
indicatif = "0.17"
tabled = "0.15"
colored = "2.1"
anyhow = "1.0"
thiserror = "1.0"
rpassword = "7.3"
*/

// ============================================================================
// src/cli/mod.rs - CLI module root
// ============================================================================

pub mod args;
pub mod commands;
pub mod ui;

pub use args::Cli;
pub use commands::CommandHandler;
pub use ui::UserInterface;

// ============================================================================
// src/cli/args.rs - Command-line argument parsing with clap
// ============================================================================

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
name = "pwm",
version,
author = "Your Name <you@example.com>",
about = "Secure local password manager",
long_about = "A secure, local-first password manager with per-entry encryption"
)]
pub struct Cli {
/// Path to vault file
#[arg(
short = 'f',
long = "vault-file",
global = true,
env = "PWM_VAULT_FILE",
default_value = "~/.local/share/pwm/vault.bin"
)]
pub vault_file: PathBuf,

    /// Verbose output
    #[arg(short = 'v', long = "verbose", global = true)]
    pub verbose: bool,

    /// Skip clipboard auto-clear (for debugging)
    #[arg(long = "no-clipboard-clear", global = true)]
    pub no_clipboard_clear: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
/// Initialize a new vault
Init {
/// Force overwrite existing vault
#[arg(short = 'f', long = "force")]
force: bool,
},

    /// Add a new password entry
    Add {
        /// Entry title
        #[arg(short = 't', long = "title")]
        title: String,

        /// Username or email
        #[arg(short = 'u', long = "username")]
        username: Option<String>,

        /// Password (if not provided, will be prompted or generated)
        #[arg(short = 'p', long = "password")]
        password: Option<String>,

        /// URL or website
        #[arg(long = "url")]
        url: Option<String>,

        /// Notes
        #[arg(short = 'n', long = "notes")]
        notes: Option<String>,

        /// Tags (comma-separated)
        #[arg(short = 'T', long = "tags")]
        tags: Option<String>,

        /// Generate random password
        #[arg(short = 'g', long = "generate")]
        generate: bool,

        /// Password length (when generating)
        #[arg(short = 'l', long = "length", default_value = "20")]
        length: usize,

        /// Enable extra protection (custom entry password)
        #[arg(long = "protected")]
        protected: bool,
    },

    /// Get and copy a password
    Get {
        /// Entry title or ID (fuzzy search)
        query: String,

        /// Copy method: clipboard, primary, auto-type
        #[arg(short = 'm', long = "method", default_value = "clipboard")]
        method: CopyMethod,

        /// Show password instead of copying
        #[arg(short = 's', long = "show")]
        show: bool,

        /// Copy username instead of password
        #[arg(long = "username")]
        username: bool,
    },

    /// List all entries
    List {
        /// Filter by tag
        #[arg(short = 't', long = "tag")]
        tag: Option<String>,

        /// Search query
        #[arg(short = 'q', long = "query")]
        query: Option<String>,

        /// Show full details
        #[arg(short = 'd', long = "details")]
        details: bool,

        /// Output format: table, json, csv
        #[arg(short = 'f', long = "format", default_value = "table")]
        format: OutputFormat,
    },

    /// Search entries
    Search {
        /// Search query
        query: String,

        /// Search in fields: title, username, url, notes, tags
        #[arg(short = 'i', long = "in", default_value = "title,username,url")]
        fields: String,
    },

    /// Update an existing entry
    Update {
        /// Entry title or ID
        query: String,

        /// New title
        #[arg(short = 't', long = "title")]
        title: Option<String>,

        /// New username
        #[arg(short = 'u', long = "username")]
        username: Option<String>,

        /// New password
        #[arg(short = 'p', long = "password")]
        password: Option<String>,

        /// Generate new password
        #[arg(short = 'g', long = "generate")]
        generate: bool,

        /// New URL
        #[arg(long = "url")]
        url: Option<String>,

        /// New notes
        #[arg(short = 'n', long = "notes")]
        notes: Option<String>,

        /// Add tags (comma-separated)
        #[arg(long = "add-tags")]
        add_tags: Option<String>,

        /// Remove tags (comma-separated)
        #[arg(long = "remove-tags")]
        remove_tags: Option<String>,
    },

    /// Delete an entry
    Delete {
        /// Entry title or ID
        query: String,

        /// Skip confirmation
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },

    /// Generate a random password
    Generate {
        /// Password length
        #[arg(short = 'l', long = "length", default_value = "20")]
        length: usize,

        /// Include lowercase letters
        #[arg(long = "lowercase", default_value = "true")]
        lowercase: bool,

        /// Include uppercase letters
        #[arg(long = "uppercase", default_value = "true")]
        uppercase: bool,

        /// Include digits
        #[arg(long = "digits", default_value = "true")]
        digits: bool,

        /// Include symbols
        #[arg(long = "symbols", default_value = "true")]
        symbols: bool,

        /// Exclude ambiguous characters (0, O, l, 1, etc.)
        #[arg(long = "no-ambiguous")]
        no_ambiguous: bool,

        /// Generate passphrase instead
        #[arg(short = 'p', long = "passphrase")]
        passphrase: bool,

        /// Number of words (for passphrase)
        #[arg(short = 'w', long = "words", default_value = "6")]
        words: usize,
    },

    /// Change master password
    ChangeMasterPassword {
        /// Skip confirmation
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },

    /// Show vault information
    Info,

    /// Export vault to JSON (encrypted)
    Export {
        /// Output file
        #[arg(short = 'o', long = "output")]
        output: PathBuf,

        /// Export format
        #[arg(short = 'f', long = "format", default_value = "json")]
        format: ExportFormat,
    },

    /// Import entries from file
    Import {
        /// Input file
        #[arg(short = 'i', long = "input")]
        input: PathBuf,

        /// Import format
        #[arg(short = 'f', long = "format", default_value = "json")]
        format: ImportFormat,
    },

    /// Create a backup
    Backup {
        /// Backup directory
        #[arg(short = 'd', long = "dir")]
        directory: Option<PathBuf>,
    },

    /// Restore from backup
    Restore {
        /// Backup file
        backup_file: PathBuf,

        /// Skip confirmation
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum CopyMethod {
Clipboard,
Primary,
AutoType,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
Table,
Json,
Csv,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ExportFormat {
Json,
Csv,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ImportFormat {
Json,
Csv,
Bitwarden,
Lastpass,
}

// ============================================================================
// src/cli/ui.rs - User interface helpers (prompts, output)
// ============================================================================

use anyhow::{Context, Result};
use colored::*;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use tabled::{
settings::Style,
Table, Tabled,
};

pub struct UserInterface {
term: Term,
theme: ColorfulTheme,
}

impl UserInterface {
pub fn new() -> Self {
Self {
term: Term::stderr(),
theme: ColorfulTheme::default(),
}
}

    // ------------------------------------------------------------------------
    // Password Prompts
    // ------------------------------------------------------------------------

    /// Prompt for master password
    pub fn prompt_master_password(&self, message: &str) -> Result<String> {
        Password::with_theme(&self.theme)
            .with_prompt(message)
            .interact()
            .context("Failed to read master password")
    }

    /// Prompt for master password with confirmation
    pub fn prompt_master_password_confirm(&self) -> Result<String> {
        loop {
            let password = Password::with_theme(&self.theme)
                .with_prompt("Enter master password")
                .interact()
                .context("Failed to read password")?;

            if password.len() < 12 {
                self.error("Master password must be at least 12 characters");
                continue;
            }

            let confirm = Password::with_theme(&self.theme)
                .with_prompt("Confirm master password")
                .interact()
                .context("Failed to read confirmation")?;

            if password == confirm {
                return Ok(password);
            } else {
                self.error("Passwords do not match. Please try again.");
            }
        }
    }

    /// Prompt for entry password (per-entry protection)
    pub fn prompt_entry_password(&self, entry_title: &str) -> Result<String> {
        Password::with_theme(&self.theme)
            .with_prompt(format!("Entry password for '{}'", entry_title))
            .interact()
            .context("Failed to read entry password")
    }

    // ------------------------------------------------------------------------
    // Text Prompts
    // ------------------------------------------------------------------------

    /// Prompt for text input
    pub fn prompt_text(&self, message: &str, default: Option<&str>) -> Result<String> {
        let mut prompt = Input::with_theme(&self.theme).with_prompt(message);

        if let Some(def) = default {
            prompt = prompt.default(def.to_string());
        }

        prompt.interact_text().context("Failed to read input")
    }

    /// Prompt for optional text input
    pub fn prompt_optional(&self, message: &str) -> Result<Option<String>> {
        let input: String = Input::with_theme(&self.theme)
            .with_prompt(format!("{} (optional)", message))
            .allow_empty(true)
            .interact_text()
            .context("Failed to read input")?;

        Ok(if input.is_empty() {
            None
        } else {
            Some(input)
        })
    }

    // ------------------------------------------------------------------------
    // Confirmations
    // ------------------------------------------------------------------------

    /// Ask for confirmation
    pub fn confirm(&self, message: &str, default: bool) -> Result<bool> {
        Confirm::with_theme(&self.theme)
            .with_prompt(message)
            .default(default)
            .interact()
            .context("Failed to read confirmation")
    }

    // ------------------------------------------------------------------------
    // Selection
    // ------------------------------------------------------------------------

    /// Select from list of options
    pub fn select<T: ToString>(&self, message: &str, items: &[T]) -> Result<usize> {
        Select::with_theme(&self.theme)
            .with_prompt(message)
            .items(items)
            .interact()
            .context("Failed to read selection")
    }

    // ------------------------------------------------------------------------
    // Output Messages
    // ------------------------------------------------------------------------

    /// Print success message
    pub fn success(&self, message: &str) {
        println!("{} {}", "✓".green().bold(), message.green());
    }

    /// Print error message
    pub fn error(&self, message: &str) {
        eprintln!("{} {}", "✗".red().bold(), message.red());
    }

    /// Print warning message
    pub fn warning(&self, message: &str) {
        println!("{} {}", "⚠".yellow().bold(), message.yellow());
    }

    /// Print info message
    pub fn info(&self, message: &str) {
        println!("{} {}", "ℹ".blue().bold(), message);
    }

    /// Print debug message (only if verbose)
    pub fn debug(&self, message: &str, verbose: bool) {
        if verbose {
            println!("{} {}", "🔍".dimmed(), message.dimmed());
        }
    }

    // ------------------------------------------------------------------------
    // Progress Indicators
    // ------------------------------------------------------------------------

    /// Show spinner with message
    pub fn spinner(&self, message: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    /// Show progress bar
    pub fn progress_bar(&self, total: u64, message: &str) -> ProgressBar {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{bar:40.cyan/blue} {pos}/{len}")
                .unwrap()
                .progress_chars("█▓▒░ "),
        );
        pb.set_message(message.to_string());
        pb
    }

    // ------------------------------------------------------------------------
    // Tables
    // ------------------------------------------------------------------------

    /// Display entries as table
    pub fn display_entries_table(&self, entries: &[EntryDisplay]) {
        if entries.is_empty() {
            self.warning("No entries found");
            return;
        }

        let table = Table::new(entries)
            .with(Style::modern())
            .to_string();

        println!("\n{}\n", table);
    }

    /// Display single entry details
    pub fn display_entry_details(&self, entry: &EntryDetailsDisplay) {
        println!("\n{}", "Entry Details".bold().underline());
        println!("{}: {}", "Title".bold(), entry.title);
        println!("{}: {}", "Username".bold(), entry.username);
        
        if let Some(url) = &entry.url {
            println!("{}: {}", "URL".bold(), url);
        }
        
        if let Some(notes) = &entry.notes {
            println!("{}: {}", "Notes".bold(), notes);
        }
        
        if !entry.tags.is_empty() {
            println!("{}: {}", "Tags".bold(), entry.tags.join(", "));
        }
        
        println!("{}: {}", "Created".bold(), entry.created);
        println!("{}: {}", "Modified".bold(), entry.modified);
        
        if entry.protected {
            println!("{}: {}", "Protection".bold(), "🔒 Extra protected".yellow());
        }
        
        println!();
    }

    // ------------------------------------------------------------------------
    // Special Output
    // ------------------------------------------------------------------------

    /// Clear screen
    pub fn clear_screen(&self) -> Result<()> {
        self.term.clear_screen().context("Failed to clear screen")
    }

    /// Display password strength
    pub fn display_password_strength(&self, password: &str, entropy: f64) {
        let strength = if entropy < 40.0 {
            "Very Weak".red()
        } else if entropy < 60.0 {
            "Weak".yellow()
        } else if entropy < 80.0 {
            "Moderate".cyan()
        } else if entropy < 100.0 {
            "Strong".green()
        } else {
            "Very Strong".bright_green()
        };

        println!("\n{}: {}", "Password Strength".bold(), strength);
        println!("{}: {:.1} bits", "Entropy".bold(), entropy);
        println!("{}: {}", "Length".bold(), password.len());
    }

    /// Display countdown
    pub fn countdown(&self, message: &str, seconds: u64) {
        for i in (1..=seconds).rev() {
            print!("\r{} {} seconds...", message, i);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            std::thread::sleep(Duration::from_secs(1));
        }
        println!("\r{} Done!          ", message);
    }
}

// ------------------------------------------------------------------------
// Display Structs for Tables
// ------------------------------------------------------------------------

#[derive(Tabled)]
pub struct EntryDisplay {
#[tabled(rename = "Title")]
pub title: String,

    #[tabled(rename = "Username")]
    pub username: String,
    
    #[tabled(rename = "URL")]
    pub url: String,
    
    #[tabled(rename = "Tags")]
    pub tags: String,
    
    #[tabled(rename = "Protected")]
    pub protected: String,
}

pub struct EntryDetailsDisplay {
pub title: String,
pub username: String,
pub url: Option<String>,
pub notes: Option<String>,
pub tags: Vec<String>,
pub created: String,
pub modified: String,
pub protected: bool,
}

// ============================================================================
// src/cli/commands.rs - Command implementations
// ============================================================================

use anyhow::{anyhow, bail, Result};
use std::path::PathBuf;

// Placeholder imports - these would come from other modules
// use crate::vault::VaultManager;
// use crate::password::PasswordGenerator;
// use crate::security::SecureCopyManager;

pub struct CommandHandler {
ui: UserInterface,
verbose: bool,
}

impl CommandHandler {
pub fn new(verbose: bool) -> Self {
Self {
ui: UserInterface::new(),
verbose,
}
}

    // ------------------------------------------------------------------------
    // Init Command
    // ------------------------------------------------------------------------

    pub fn handle_init(&self, vault_file: &PathBuf, force: bool) -> Result<()> {
        self.ui.info(&format!("Initializing vault at: {}", vault_file.display()));

        // Check if vault already exists
        if vault_file.exists() && !force {
            bail!("Vault already exists. Use --force to overwrite.");
        }

        // Prompt for master password
        let master_password = self.ui.prompt_master_password_confirm()?;

        // Show password strength
        let entropy = calculate_entropy(&master_password);
        self.ui.display_password_strength(&master_password, entropy);

        if entropy < 60.0 {
            let proceed = self.ui.confirm(
                "Password strength is weak. Continue anyway?",
                false,
            )?;
            if !proceed {
                bail!("Vault initialization cancelled");
            }
        }

        // Create vault
        let spinner = self.ui.spinner("Creating vault...");
        
        // TODO: Call vault_manager.initialize(vault_file, &master_password)?;
        std::thread::sleep(Duration::from_secs(1)); // Simulate work
        
        spinner.finish_with_message("Vault created!");

        self.ui.success(&format!("Vault initialized at {}", vault_file.display()));
        self.ui.warning("⚠ Remember your master password! It cannot be recovered.");

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Add Command
    // ------------------------------------------------------------------------

    pub fn handle_add(
        &self,
        vault_file: &PathBuf,
        title: String,
        username: Option<String>,
        password: Option<String>,
        url: Option<String>,
        notes: Option<String>,
        tags: Option<String>,
        generate: bool,
        length: usize,
        protected: bool,
    ) -> Result<()> {
        // Unlock vault
        let master_password = self.ui.prompt_master_password("Enter master password")?;
        
        let spinner = self.ui.spinner("Unlocking vault...");
        // TODO: let mut vault = vault_manager.unlock(vault_file, &master_password)?;
        spinner.finish_and_clear();

        // Get username
        let username = match username {
            Some(u) => u,
            None => self.ui.prompt_text("Username", None)?,
        };

        // Get password
        let password = if generate {
            // TODO: let generated = password_generator.generate(length, ...)?;
            let generated = format!("Generated_Password_{}", length);
            self.ui.success(&format!("Generated password: {}", generated));
            generated
        } else {
            match password {
                Some(p) => p,
                None => {
                    let use_generated = self.ui.confirm("Generate random password?", true)?;
                    if use_generated {
                        // TODO: password_generator.generate(20, ...)?
                        "Generated_Password_20".to_string()
                    } else {
                        self.ui.prompt_master_password("Enter password")?
                    }
                }
            }
        };

        // Get optional fields
        let url = url.or_else(|| self.ui.prompt_optional("URL").ok().flatten());
        let notes = notes.or_else(|| self.ui.prompt_optional("Notes").ok().flatten());
        
        let tags_vec: Vec<String> = tags
            .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        // Get entry password if protected
        let entry_password = if protected {
            let pw = self.ui.prompt_entry_password(&title)?;
            Some(pw)
        } else {
            None
        };

        // Add entry
        let spinner = self.ui.spinner("Adding entry...");
        // TODO: vault.add_entry(title, username, password, url, notes, tags_vec, entry_password)?;
        std::thread::sleep(Duration::from_millis(500));
        spinner.finish_and_clear();

        self.ui.success(&format!("Entry '{}' added successfully", title));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Get Command
    // ------------------------------------------------------------------------

    pub fn handle_get(
        &self,
        vault_file: &PathBuf,
        query: String,
        method: CopyMethod,
        show: bool,
        username: bool,
    ) -> Result<()> {
        // Unlock vault
        let master_password = self.ui.prompt_master_password("Enter master password")?;
        
        let spinner = self.ui.spinner("Unlocking vault...");
        // TODO: let vault = vault_manager.unlock(vault_file, &master_password)?;
        spinner.finish_and_clear();

        // Search for entry
        // TODO: let entries = vault.search(&query)?;
        
        // Simulate search results
        let entries = vec!["GitHub", "Gmail"];
        
        if entries.is_empty() {
            bail!("No entries found matching '{}'", query);
        }

        let selected = if entries.len() > 1 {
            self.ui.select("Multiple entries found. Select one:", &entries)?
        } else {
            0
        };

        let entry_title = entries[selected];

        // Check if entry requires password
        // TODO: if entry.is_protected() {
        //     let entry_password = self.ui.prompt_entry_password(entry_title)?;
        //     // Unlock entry
        // }

        // Get password or username
        let value_to_copy = if username {
            "user@example.com".to_string() // TODO: entry.username
        } else {
            "password123".to_string() // TODO: entry.password
        };

        if show {
            println!("\n{}: {}\n", entry_title.bold(), value_to_copy);
        } else {
            // Copy to clipboard
            // TODO: secure_copy.copy(&value_to_copy, method)?;
            self.ui.success(&format!("Password copied to clipboard"));
            self.ui.info("Will auto-clear in 30 seconds");
        }

        Ok(())
    }

    // ------------------------------------------------------------------------
    // List Command
    // ------------------------------------------------------------------------

    pub fn handle_list(
        &self,
        vault_file: &PathBuf,
        tag: Option<String>,
        query: Option<String>,
        details: bool,
        format: OutputFormat,
    ) -> Result<()> {
        // Unlock vault
        let master_password = self.ui.prompt_master_password("Enter master password")?;
        
        let spinner = self.ui.spinner("Loading entries...");
        // TODO: let vault = vault_manager.unlock(vault_file, &master_password)?;
        // TODO: let entries = vault.list_entries(tag, query)?;
        spinner.finish_and_clear();

        // Simulate entries
        let entries = vec![
            EntryDisplay {
                title: "GitHub".to_string(),
                username: "user@example.com".to_string(),
                url: "https://github.com".to_string(),
                tags: "work, dev".to_string(),
                protected: "".to_string(),
            },
            EntryDisplay {
                title: "Gmail".to_string(),
                username: "user@gmail.com".to_string(),
                url: "https://gmail.com".to_string(),
                tags: "personal".to_string(),
                protected: "🔒".to_string(),
            },
        ];

        match format {
            OutputFormat::Table => {
                self.ui.display_entries_table(&entries);
            }
            OutputFormat::Json => {
                // TODO: Serialize to JSON
                println!("{{\"entries\": []}}");
            }
            OutputFormat::Csv => {
                // TODO: Serialize to CSV
                println!("title,username,url,tags");
            }
        }

        Ok(())
    }

    // Additional command handlers would follow similar patterns...
}

// Helper function
fn calculate_entropy(password: &str) -> f64 {
let mut charset_size = 0;
if password.chars().any(|c| c.is_lowercase()) {
charset_size += 26;
}
if password.chars().any(|c| c.is_uppercase()) {
charset_size += 26;
}
if password.chars().any(|c| c.is_numeric()) {
charset_size += 10;
}
if password.chars().any(|c| !c.is_alphanumeric()) {
charset_size += 32;
}

    (password.len() as f64) * (charset_size as f64).log2()
}

// ============================================================================
// USAGE EXAMPLE in main.rs
// ============================================================================

/*
use clap::Parser;
use anyhow::Result;

fn main() -> Result<()> {
let cli = Cli::parse();
let handler = CommandHandler::new(cli.verbose);

    match cli.command {
        Commands::Init { force } => {
            handler.handle_init(&cli.vault_file, force)?;
        }
        Commands::Add { 
            title, username, password, url, notes, tags,
            generate, length, protected 
        } => {
            handler.handle_add(
                &cli.vault_file, title, username, password,
                url, notes, tags, generate, length, protected
            )?;
        }
        Commands::Get { query, method, show, username } => {
            handler.handle_get(&cli.vault_file, query, method, show, username)?;
        }
        Commands::List { tag, query, details, format } => {
            handler.handle_list(&cli.vault_file, tag, query, details, format)?;
        }
        // ... other commands
        _ => {
            eprintln!("Command not yet implemented");
        }
    }

    Ok(())
}
*/