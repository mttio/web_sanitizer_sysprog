/*
The tool must accept one or more inputs
local HTML/asset files, a directory tree, or a list of URLs to fetch
*/

use crate::cli_application::http_client::SanitizerHttpClient;
use crate::sanitizer_engine::concurrency::ThreadPool;
use crate::sanitizer_engine::engine_structs::InputSource;
use crate::sanitizer_engine::errors::{DangerousDomain, IDN};
use crate::sanitizer_engine::html::create_rewriter;
use crate::sanitizer_engine::log::{LogLevel, Logger};
use crate::sanitizer_engine::policy::Policy;
use crate::sanitizer_engine::url::{RuleMatch, check_domain};
use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde_json;
use std::fs::{self, File};
use std::io::{BufReader, Read};
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

/// Run the CLI application
pub async fn run() -> Result<()> {
    let args = Args::parse();

    println!("Successfully parsed args: {:?}", args);

    // Load policy
    let policy = match &args.policy {
        Some(path) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read policy file: {path:?}"))?;
            serde_json::from_str(&content).context("Failed to parse policy file")?
        }
        None => Policy::default(),
    };

    // println!("Successfully loaded policy: {policy:#?}");

    // let subscriber = FmtSubscriber::builder()
    //     .with_max_level(Level::TRACE)
    //     .finish();

    // tracing::subscriber::set_global_default(subscriber)?;

    // Prepare inputs
    let mut sources = Vec::new();
    for input in args.inputs {
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

    // No-sources case
    if sources.is_empty() {
        println!("No valid inputs provided.");
        return Ok(());
    }

    // println!("Successfully created input sources vector: {:?}", sources);

    // Ensure output directory exists
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {:?}", args.output_dir))?;

    println!(
        "Successfully created output directory: {:?}",
        args.output_dir
    );

    let client = SanitizerHttpClient::new(&policy).await?;
    let client = Arc::new(client);
    let policy = Arc::new(policy);
    let max_size = (sources.len() as f64).log10().ceil() as usize;

    let pool = ThreadPool::new(args.workers); //thread pool is created with args.workers ready to work
    let rt_handle = tokio::runtime::Handle::current();
    let output_dir = Arc::new(args.output_dir);

    sources.into_iter().enumerate().for_each(|(i, source)| {
        let logger = Logger {
            path: Arc::new(PathBuf::new()),
            index: i,
            max_size,
        };
        let client = Arc::clone(&client);
        let policy = Arc::clone(&policy);
        let rt_handle = rt_handle.clone();
        let output_dir = Arc::clone(&output_dir);

        pool.push_job(move || {
            match source {
                InputSource::Url(url) => {
                    if let Some(original) = check_domain(&url)
                        && let Err(e) = policy.urls.idn_action.handle_error(&logger, IDN(original))
                    {
                        logger.error(e);
                        return;
                    }

                    if let Some(host) = url.host().map(|x| x.to_owned())
                        && policy
                            .urls
                            .dangerous_domains
                            .iter()
                            .any(|x| host.matches(&x.0))
                        && let Err(e) = policy
                            .connections
                            .dangerous_domain_action
                            .handle_error(&logger, DangerousDomain(host.to_owned()))
                    {
                        logger.error(e);
                        return;
                    }

                    let output_path = output_dir.join(format!("{i}.html"));
                    let output = match File::create(&output_path) {
                        Ok(file) => file,
                        Err(e) => {
                            logger.error(anyhow!("Failed to create output file {:?}: {}", output_path, e));
                            return;
                        }
                    };

                    let fetch_result = rt_handle.block_on(async {
                        client.fetch_one_url(&url, &logger, output, &policy).await
                    });

                    match fetch_result {
                        Ok(_) => {}
                        Err(error) => {
                            logger.log(LogLevel::Error, anyhow!("Could not fetch url {}: {}", url, error));
                        }
                    }
                }
                InputSource::File(path) => {
                    let output_path = output_dir.join(format!("{i}.html"));
                    let file_result = || -> Result<()> {
                        let input_file = File::open(&path)
                            .with_context(|| format!("Failed to open local file {:?}", path))?;
                        let mut reader = BufReader::new(input_file);
                        let output_file = File::create(&output_path)
                            .with_context(|| format!("Failed to create output file {:?}", output_path))?;
                        
                        let mut rewriter = create_rewriter(&logger, &policy, output_file);
                        let mut buffer = [0; 8192];
                        loop {
                            let n = reader.read(&mut buffer)
                                .with_context(|| format!("Failed to read chunk from file {:?}", path))?;
                            if n == 0 {
                                break;
                            }
                            rewriter.write(&buffer[..n])
                                .map_err(|e| anyhow!("Rewriter write error: {:?}", e))?;
                        }
                        rewriter.end()
                            .map_err(|e| anyhow!("Rewriter end error: {:?}", e))?;
                        Ok(())
                    }();

                    match file_result {
                        Ok(_) => {}
                        Err(error) => {
                            logger.log(LogLevel::Error, error);
                        }
                    }
                }
            }
        });
    });

    drop(pool); // This blocks until all jobs are executed

    Ok(())
}

/*======================== HELPERS ============================*/

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
