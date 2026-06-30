/*
The tool must accept one or more inputs
local HTML/asset files, a directory tree, or a list of URLs to fetch
*/

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use std::fs::{self};
use web_sanitizer_sysprog::engine_structs::InputSource;
use web_sanitizer_sysprog::log::logging_thread;
use web_sanitizer_sysprog::policy::Policy;

use std::path::PathBuf;
use std::sync::Arc;
use url::Url;
use walkdir::WalkDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.generate_policy {
        let string = toml::to_string_pretty(&Policy::default())
            .context("Failed to serialize default policy")?;
        println!("{string}");
        return Ok(());
    };

    println!(
        "{}",
        r#"
    ____                  __                  
   / __ \___  ____  ___  / /___  ____  ___    
  / /_/ / _ \/ __ \/ _ \/ / __ \/ __ \/ _ \   
 / ____/  __/ / / /  __/ / /_/ / /_/ /  __/   
/_/    \___/_/ /_/\___/_/\____/ .___/\___/    
                             /_/              
"#
        .cyan()
        .bold()
    );
    println!(
        "{}",
        "[+] Welcome to the Penelope Web Sanitizer CLI Interface"
            .bright_blue()
            .bold()
    );
    println!(
        "{}",
        "==========================================================".bright_blue()
    );

    //run cli application
    match run(args) {
        Ok(true) => {
            println!(
                "{}",
                "======================== GOODBYE ========================="
                    .bright_black()
                    .bold()
            );
            std::process::exit(0);
        }
        Ok(false) => {
            println!(
                "{}",
                "======================== GOODBYE ========================="
                    .bright_black()
                    .bold()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{} {:?}", "Application error:".red().bold(), e);
            println!(
                "{}",
                "======================== GOODBYE ========================="
                    .bright_black()
                    .bold()
            );
            std::process::exit(1);
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Input files, directories or URLs
    #[arg(required_unless_present = "generate_policy")]
    pub inputs: Vec<String>,

    /// Policy configuration file (.toml)
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

    /// Print the default policy
    #[arg(short, long)]
    pub generate_policy: bool,
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
/// * `Result<bool>` - `Ok(true)` if clean/no blocklist errors, `Ok(false)` if blocked/denied content occurred, or an error if initialization fails.
pub fn run(args: Args) -> Result<bool> {
    let policy = load_policy(args.policy.as_ref())?;

    // Print argument summary
    println!(
        "\n{}",
        "[SYSTEM] ACTIVE CONFIGURATION SUMMARY:"
            .bright_blue()
            .bold()
    );
    println!("  [Inputs]:     {:?}", args.inputs);
    println!(
        "  [Policy]:     {}",
        match &args.policy {
            Some(p) => format!("{:?}", p),
            None => "Default Embedded Policy".to_owned(),
        }
    );
    println!("  [Output Dir]: {:?}", args.output_dir);
    println!("  [Workers]:    {}", args.workers.to_string().yellow());
    println!();

    let sources = parse_inputs(args.inputs)?;

    if sources.is_empty() {
        println!("{}", "[!] No valid inputs provided.".yellow());
        return Ok(true);
    }

    // Step 1: Clean output directory
    println!(
        "{}",
        "[1/3] Cleaning output folder...".bright_black().bold()
    );
    if args.output_dir.exists() {
        fs::remove_dir_all(&args.output_dir)
            .with_context(|| format!("Failed to empty output directory: {:?}", args.output_dir))?;
    }
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {:?}", args.output_dir))?;

    // Step 2: Initialize parallel pipeline
    println!(
        "{}",
        "[2/3] Initializing parallel sanitization pipeline..."
            .bright_black()
            .bold()
    );
    let (tx, rx) = std::sync::mpsc::channel();

    let policy = Arc::new(policy);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.workers)
        .enable_time()
        .enable_io()
        .build()?;
    let output_dir = Arc::new(args.output_dir);
    let max_size = sources.len();

    // Step 3: Run and log
    println!(
        "{}",
        "[3/3] Processing inputs & streaming logs..."
            .bright_black()
            .bold()
    );
    let library_result = web_sanitizer_sysprog::library(
        &runtime,
        sources,
        Arc::clone(&policy),
        Arc::clone(&output_dir),
        tx,
    );

    match library_result {
        Ok(_) => {
            let has_errors = logging_thread(&output_dir, &policy, max_size, rx);
            if has_errors {
                println!("\n{}", "[-] Execution complete with policy blocks/errors. Checked files have been processed.".red().bold());
                Ok(false)
            } else {
                println!(
                    "\n{}",
                    "[+] Execution complete! Checked files have been processed."
                        .bright_blue()
                        .bold()
                );
                Ok(true)
            }
        }
        Err(e) => {
            println!("\n{}", "[-] Sanitization failed with error:".red().bold());
            Err(e.into())
        }
    }
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
