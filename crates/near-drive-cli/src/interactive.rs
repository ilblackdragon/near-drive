//! Prompts for interactive mode (same `inquire` library and look as near-cli-rs).
//!
//! Every prompt is skipped when its value was given on the command line; when
//! stdin/stderr are not terminals (or `--no-interactive`), a missing value is an
//! error instead of a prompt.
use anyhow::{bail, Context, Result};
use inquire::{Confirm, Select, Text};
use std::fmt;

pub struct Prompter {
    pub enabled: bool,
    /// Set once any prompt ran: the caller then prints the equivalent command.
    pub used: bool,
}

#[derive(Clone)]
pub struct Choice<T> {
    pub value: T,
    pub label: String,
}

impl<T> fmt::Display for Choice<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

pub fn choice<T>(value: T, label: impl Into<String>) -> Choice<T> {
    Choice { value, label: label.into() }
}

fn cancelled(e: inquire::InquireError) -> anyhow::Error {
    match e {
        inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted => anyhow::anyhow!("cancelled"),
        e => anyhow::Error::new(e).context("prompt failed"),
    }
}

impl Prompter {
    pub fn new(enabled: bool) -> Self {
        Self { enabled, used: false }
    }

    fn start(&mut self, what: &str, flag: &str) -> Result<()> {
        if !self.enabled {
            bail!("missing {what} ({flag}); run in a terminal to be asked for it");
        }
        self.used = true;
        Ok(())
    }

    /// `value` if given, else ask. `flag` names the argument for the error.
    pub fn text(&mut self, value: Option<String>, msg: &str, flag: &str, initial: Option<&str>, help: Option<&str>) -> Result<String> {
        if let Some(v) = value {
            return Ok(v);
        }
        self.start(msg, flag)?;
        let mut t = Text::new(msg);
        if let Some(i) = initial {
            t = t.with_initial_value(i);
        }
        if let Some(h) = help {
            t = t.with_help_message(h);
        }
        t.prompt().map_err(cancelled)
    }

    /// A `near://` URI: given, or asked until it parses.
    pub fn uri(&mut self, value: Option<String>, msg: &str, initial: &str, help: Option<&str>) -> Result<String> {
        if let Some(v) = value {
            return Ok(v);
        }
        self.start(msg, "URI")?;
        let mut t = Text::new(msg).with_initial_value(initial).with_validator(|s: &str| {
            Ok(match near_drive_client::near_drive_core::NearUri::parse(s) {
                Ok(_) => inquire::validator::Validation::Valid,
                Err(e) => inquire::validator::Validation::Invalid(e.to_string().into()),
            })
        });
        if let Some(h) = help {
            t = t.with_help_message(h);
        }
        t.prompt().map_err(cancelled)
    }

    /// Like [`text`](Self::text) but an empty answer is `None`.
    pub fn optional_text(&mut self, msg: &str, help: Option<&str>) -> Result<Option<String>> {
        self.used = true;
        let mut t = Text::new(msg);
        if let Some(h) = help {
            t = t.with_help_message(h);
        }
        let s = t.prompt().map_err(cancelled)?;
        Ok(Some(s.trim().to_string()).filter(|s| !s.is_empty()))
    }

    pub fn select<T: Clone>(&mut self, msg: &str, flag: &str, options: Vec<Choice<T>>) -> Result<T> {
        self.start(msg, flag)?;
        Ok(Select::new(msg, options).with_page_size(15).prompt().map_err(cancelled)?.value)
    }

    pub fn confirm(&mut self, msg: &str, default: bool) -> Result<bool> {
        if !self.enabled {
            return Ok(default);
        }
        self.used = true;
        Confirm::new(msg).with_default(default).prompt().map_err(cancelled)
    }

    /// Account to act as: given, or picked from the accounts near-cli knows.
    pub fn account(&mut self, value: Option<String>, known: Vec<String>) -> Result<String> {
        if let Some(v) = value {
            return Ok(v);
        }
        if !self.enabled {
            bail!("--account (or NEAR_DRIVE_ACCOUNT) is required");
        }
        const OTHER: &str = "\u{0}other";
        let mut opts: Vec<Choice<String>> = known.into_iter().map(|a| choice(a.clone(), a)).collect();
        if opts.is_empty() {
            return self.text(None, "NEAR account:", "--account", None, Some("e.g. alice.near; its keys must be in near-cli (`near account import-account`)"));
        }
        opts.push(choice(OTHER.to_string(), "another account…"));
        let a = self.select("Which account?", "--account", opts)?;
        if a == OTHER {
            return self.text(None, "NEAR account:", "--account", None, None);
        }
        Ok(a)
    }
}

/// Validate-on-use helper for comma-separated account lists typed at a prompt.
pub fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

pub fn basename(path: &str) -> Result<String> {
    path.trim_end_matches('/').rsplit('/').next().filter(|s| !s.is_empty()).map(str::to_string).context("path has no file name")
}
