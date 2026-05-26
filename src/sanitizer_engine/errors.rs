use std::{error::Error, fmt::Display};

use colored::Colorize;
use url::Host;

#[derive(Debug)]
pub struct TooManyRedirects;
impl Error for TooManyRedirects {}
impl Display for TooManyRedirects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("too many redirects")
    }
}

#[derive(Debug)]
pub struct DangerousDomain(pub Host);
impl Error for DangerousDomain {}
impl Display for DangerousDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dangerous domain ({})", self.0.to_string().bright_cyan())
    }
}

#[derive(Debug)]
pub struct IDN(pub String);
impl Error for IDN {}
impl Display for IDN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IDN url ({})", self.0)
    }
}

pub fn trace<E: Into<Box<dyn Error>>>(error: E) {
    println!(
        "{}: {}",
        "  TRACE".bright_black().bold(),
        error.into().to_string().italic()
    );
}

pub fn warn<E: Into<Box<dyn Error>>>(error: E) {
    println!(
        "{}: {}",
        "WARNING".bright_yellow().bold(),
        error.into().to_string().italic()
    );
}

pub fn error<E: Into<Box<dyn Error>>>(error: E) {
    println!(
        "{}: {}",
        "  ERROR".bright_red().bold(),
        error.into().to_string().italic()
    );
}
