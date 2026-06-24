/*
The tool must accept one or more inputs
local HTML/asset files, a directory tree, or a list of URLs to fetch
*/

use crate::cli_application::http_client::SanitizerHttpClient;
use crate::sanitizer_engine::crawl_session::CrawlSession;
use crate::sanitizer_engine::engine_structs::InputSource;
use crate::sanitizer_engine::log::{Logger, logging_thread};
use crate::sanitizer_engine::policy::Policy;
use anyhow::{Context, Result};
use clap::Parser;
use futures_util::future::lazy;
use parking_lot::Mutex;
use std::fs::{self};

use std::path::PathBuf;
use std::sync::Arc;
use url::Url;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Input files, directories or URLs
    #[arg(required = true, num_args = 1..)]
    pub inputs: Vec<String>,

    /// Policy configuration file (JSON)
    #[arg(short, long)]
    pub policy: Option<PathBuf>,

    /// Output directory for sanitised content and reports
    #[arg(short, long, default_value = "output")]
    pub output_dir: PathBuf,

    /// Number of concurrent workers
    #[arg(short, long, default_value_t = 4)]
    pub workers: usize,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// Helper to load the sanitization policy from a JSON file.
///
/// # Inputs
/// * `path` - Optional path reference to the JSON policy file.
///
/// # Returns
/// * `Result<Policy>` - The parsed `Policy` struct, or the default Policy if no path is given. Returns an error if reading or parsing fails.
fn load_policy(path: Option<&PathBuf>) -> Result<Policy> {
    let policy = match path {
        Some(path) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read policy file: {path:?}"))?;
            toml::from_str(&content).context("Failed to parse policy file")?
        }
        None => Policy::default(),
    };
    Ok(policy)
}

/// Helper to parse input patterns (URLs, directory paths, or files) into concrete InputSources.
///
/// # Inputs
/// * `inputs` - A vector of input strings.
///
/// # Returns
/// * `Result<Vec<InputSource>>` - A list of successfully parsed input sources (files and URLs).
fn parse_inputs(inputs: Vec<String>) -> Result<Vec<InputSource>> {
    let mut sources = Vec::new();
    for input in inputs {
        // Try to parse as URL first
        if let Ok(url) = Url::parse(&input)
            && (url.scheme() == "http" || url.scheme() == "https")
        {
            println!("Input '{}' recognized as URL", input);
            sources.push(InputSource::Url(url.clone()));
        } else {
            let path = PathBuf::from(&input);
            if path.is_dir() {
                println!("Input '{}' recognized as Directory", input);
                // Explore directory recursively
                for entry in WalkDir::new(&path) {
                    let entry = entry
                        .with_context(|| format!("Failed to read directory entry in {:?}", path))?;
                    if entry.file_type().is_file() {
                        sources.push(InputSource::File(entry.path().to_path_buf()));
                    }
                }
            } else if path.is_file() {
                println!("Input '{}' recognized as File", input);
                sources.push(InputSource::File(path));
            } else {
                println!(
                    "Warning: Input '{}' not found or not a supported URL scheme. Skipping.",
                    input
                );
            }
        }
    }
    Ok(sources)
}

/// Runs the main CLI application workflow: parses args, loads policy, submits jobs to the thread pool, and blocks until completion.
///
/// # Inputs
/// * None (inputs are gathered from command line arguments via `Args::parse()`).
///
/// # Returns
/// * `Result<()>` - `Ok(())` on successful completion, or an error if initialization fails.
pub fn run() -> Result<()> {
    let args = Args::parse();
    println!("Successfully parsed args: {:?}", args);

    let policy = load_policy(args.policy.as_ref())?;
    let sources = parse_inputs(args.inputs)?;

    if sources.is_empty() {
        println!("No valid inputs provided.");
        return Ok(());
    }

    // Ensure output directory exists
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {:?}", args.output_dir))?;

    println!(
        "Successfully created output directory: {:?}",
        args.output_dir
    );

    let (tx, rx) = std::sync::mpsc::channel();
    let url_map = Arc::new(Mutex::new(
        sources
            .iter()
            .enumerate()
            .flat_map(|(i, source)| match source {
                InputSource::File(_) => None,
                InputSource::Url(url) => Some((url.clone(), i)),
            })
            .collect(),
    ));

    let policy = Arc::new(policy);

    let client = Arc::new(SanitizerHttpClient::new(
        policy.clone(),
        tx.clone(),
        url_map.clone(),
    )?);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.workers)
        .enable_time()
        .enable_io()
        .build()?;
    let output_dir = Arc::new(args.output_dir);
    let max_size = sources.len();

    for (i, source) in sources.into_iter().enumerate() {
        let logger = Logger {
            index: i,
            channel: tx.clone(),
        };

        let session = Arc::new(CrawlSession::new(
            Arc::clone(&client),
            Arc::clone(&policy),
            logger,
            runtime.handle().clone(),
            Arc::clone(&output_dir),
            Arc::clone(&url_map),
        ));

        match source {
            InputSource::Url(url) => runtime.spawn(async { session.process_url(url).await }),
            InputSource::File(path) => runtime.spawn(lazy(move |_| session.process_file(path))),
        };
    }

    // Drop excess resources
    drop(tx);
    drop(client);

    logging_thread(&output_dir, &policy, max_size, rx);

    Ok(())
}

/*======================== HELPERS ============================*/

/// Helper to determine if a directory entry starts with a dot (hidden file/folder).
///
/// # Inputs
/// * `entry` - A reference to the walkdir entry.
///
/// # Returns
/// * `bool` - `true` if the entry name starts with a dot, otherwise `false`.
#[allow(dead_code)]
fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

/*======================== TESTS ============================*/

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_default_args() {
        let args = Args::try_parse_from(["test", "input1.html"]).unwrap();
        assert_eq!(args.inputs, vec!["input1.html"]);
        assert_eq!(args.policy, None);
        assert_eq!(args.output_dir, PathBuf::from("output"));
        assert_eq!(args.workers, 4);
        assert!(!args.verbose);
    }

    #[test]
    fn test_multiple_inputs() {
        let args =
            Args::try_parse_from(["test", "input1.html", "input2.html", "http://example.com"])
                .unwrap();
        assert_eq!(
            args.inputs,
            vec!["input1.html", "input2.html", "http://example.com"]
        );
    }

    #[test]
    fn test_custom_flags() {
        let args = Args::try_parse_from([
            "test",
            "input.html",
            "--policy",
            "custom_policy.json",
            "--output-dir",
            "custom_output",
            "--workers",
            "8",
            "--verbose",
        ])
        .unwrap();
        assert_eq!(args.policy, Some(PathBuf::from("custom_policy.json")));
        assert_eq!(args.output_dir, PathBuf::from("custom_output"));
        assert_eq!(args.workers, 8);
        assert!(args.verbose);
    }

    #[test]
    fn test_missing_input_fails() {
        let result = Args::try_parse_from(["test"]);
        assert!(result.is_err());
    }
}
