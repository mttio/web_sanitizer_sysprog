use std::fmt::Display;

use anyhow::anyhow;
use colored::Colorize;
use hickory_resolver::net::NetError;
use lol_html::errors::RewritingError;
use thiserror::Error;
use url::{Host, Url};

/// An error that the sanitizer can produce
#[derive(Debug, Error)]
#[error(transparent)]
pub enum SanitizerError {
    #[error("DNS resolution timed out for host: {}", .0)]
    Timeout(String),
    #[error("DNS lookup failed for host {}: {}", .0, .1)]
    DnsLookup(String, NetError),
    #[error("too many redirects (max = {})", .0.to_string().bright_cyan())]
    TooManyRedirects(usize),
    #[error("Only HTTPS URLs are permitted")]
    NonHttpsUrl,
    #[error("dangerous domain ({})", .0.to_string().bright_cyan())]
    DangerousDomain(Host),
    #[error("dangerous domain ({}) @ {}", .0.to_string().bright_cyan(), .1.to_string().bright_magenta())]
    DangerousDomainInHtml(Host, usize),
    #[error(
        "event handler ({}){}",
        .0.bright_cyan(),
        match .1 {
            Some(x) => format!(" @ {}", x.to_string().bright_magenta()),
            None => "".to_owned(),
        }        
    )]
    EventHandler(String, Option<usize>),
    #[error(
        "dangerous URI ({}){}",
        .0.bright_cyan(),
        match .1 {
            Some(x) => format!(" @ {}", x.to_string().bright_magenta()),
            None => "".to_owned(),
        }
    )]
    DangerousUri(String, Option<usize>),
    #[error("IDN url ({})", .0)]
    Idn(String),
    #[error(
        "blocked script (source = {}) @ {}",
        .0.bright_cyan(),
        .1.to_string().bright_magenta(),
    )]
    BlockedScript(String, usize),
    #[error(
        "response body exceeds maximum size ({} bytes)",
        .0.to_string().bright_cyan(),        
    )]
    ContentTooLong(usize),
    #[error(
        "MIME mismatch (declared = {}, sniffed = {})",
        .0.as_deref().unwrap_or("<none>"),
        .1.as_deref().unwrap_or("<none>"),
    )]
    MimeMismatch(Option<String>, Option<String>),
    #[error("Sub-resource crawl limit reached: max_requests = {}", .0)]
    MaxSubresources(usize),
    #[error("Sub-resource crawl depth limit reached: max_requests = {}", .0)]
    MaxSubresourceDepth(usize),
    #[error("Failed to fetch sub-resource {0}: {1}")]
    SubresourceFetch(Url, Box<Self>),
    #[error("Unknown resource type")]
    UnknownResourceType,
    #[error("Rewriting error: {0}")]
    Rewriting(#[source] RewritingError),
    #[error("custom XML entity declaration detected (potential XML bomb)")]
    XmlEntityDeclaration,
    #[error("embedded active content ({0}) detected")]
    ActiveContent(String),
    Other(#[from] anyhow::Error),
}

/// A message that the sanitizer can produce
#[derive(Debug)]
pub enum SanitizerMessage {
    Error(SanitizerError),
    CrawlingSubresource { depth: usize, url: Url },
}

impl Display for SanitizerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error(e) => write!(f, "{e}"),
            Self::CrawlingSubresource { depth, url } => {
                write!(
                    f,
                    "Crawling sub-resource (depth {}): {}",
                    depth,
                    url.to_string().bright_blue()
                )
            }
        }
    }
}

impl<T: Into<SanitizerError>> From<T> for SanitizerMessage {
    fn from(value: T) -> Self {
        Self::Error(value.into())
    }
}

impl From<RewritingError> for SanitizerError {
    fn from(value: RewritingError) -> Self {
        match value {
            RewritingError::ContentHandlerError(e) => {
                // Extract the error returned inside the `element!()` macro
                match e.downcast::<SanitizerError>() {
                    Ok(e) => *e,
                    Err(e) => SanitizerError::Other(anyhow!("{e}"))
                }                    
            }
            e => SanitizerError::Rewriting(e),            
        }
    }
}

pub type LoggerError = Box<dyn std::error::Error + Send + Sync>;
