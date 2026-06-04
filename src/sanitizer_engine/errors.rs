use std::{error::Error, fmt::Display};

use colored::Colorize;
use url::Host;

#[derive(Debug)]
pub struct TimeoutError(pub String);
impl Error for TimeoutError {}
impl Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNS resolution timed out for host: {}", self.0)
    }
}

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
pub struct DangerousDomainInHtml(pub Host, pub usize);
impl Error for DangerousDomainInHtml {}
impl Display for DangerousDomainInHtml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dangerous domain ({}) @ {}",
            self.0.to_string().bright_cyan(),
            self.1.to_string().bright_magenta(),
        )
    }
}

#[derive(Debug)]
pub struct EventHandler(pub String, pub Option<usize>);
impl Error for EventHandler {}
impl Display for EventHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "event handler ({}){}",
            self.0.bright_cyan(),
            match self.1 {
                Some(x) => format!(" @ {}", x.to_string().bright_magenta()),
                None => "".to_owned(),
            }
        )
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

#[derive(Debug)]
pub struct ContentTooLong(pub usize);
impl Error for ContentTooLong {}
impl Display for ContentTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "response body exceeds maximum size limit of {} bytes",
            self.0.to_string().bright_cyan()
        )
    }
}

pub type LoggerError = Box<dyn Error + Send + Sync>;
