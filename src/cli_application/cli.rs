/*
The tool must accept one or more inputs
local HTML/asset files, a directory tree, or a list of URLs to fetch
*/

use crate::cli_application::http_client::SanitizerHttpClient;
use crate::sanitizer_engine::concurrency::ThreadPool;
use crate::sanitizer_engine::engine_structs::InputSource;
use crate::sanitizer_engine::errors::{DangerousDomain, IDN, ContentTooLong};
use crate::sanitizer_engine::html::{create_rewriter, create_rewriter_with_crawler};
use crate::sanitizer_engine::log::{LogLevel, Logger};
use crate::sanitizer_engine::policy::Policy;
use crate::sanitizer_engine::url::{RuleMatch, check_domain};
use crate::sanitizer_engine::resource_sanitizer::validate_mime;
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
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
            serde_json::from_str(&content).context("Failed to parse policy file")?
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

/// Helper to fetch and sanitize a URL source, crawling its sub-resources recursively.
///
/// # Inputs
/// * `url` - The remote URL to sanitize.
/// * `index` - The worker/input index for file naming.
/// * `client` - The HTTP sanitizer client.
/// * `policy` - The security policy configuration.
/// * `logger` - The logging interface.
/// * `rt_handle` - The Tokio runtime handle to block on async tasks.
/// * `output_dir` - The path to the directory where results are written.
///
/// # Returns
/// * None
fn process_url(
    url: Url,
    index: usize,
    client: &SanitizerHttpClient,
    policy: &Policy,
    logger: &Logger,
    rt_handle: &tokio::runtime::Handle,
    output_dir: &PathBuf,
) {
    if let Some(original) = check_domain(&url)
        && let Err(e) = policy.urls.idn_action.handle_error(logger, IDN(original))
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
            .handle_error(logger, DangerousDomain(host.to_owned()))
    {
        logger.error(e);
        return;
    }

    let output_path = output_dir.join(format!("{index}.html"));
    let fetch_result = rt_handle.block_on(async {
        client.fetch_and_crawl(&url, logger, &output_path, policy).await
    });

    if let Err(error) = fetch_result {
        logger.error(anyhow!("Could not fetch url {}: {}", url, error));
    }
}

/// Helper to process and sanitize a local file, downloading and sanitizing its remote sub-resources if configured.
///
/// # Inputs
/// * `path` - The local file path to process.
/// * `index` - The worker/input index for file naming.
/// * `client` - The HTTP sanitizer client used to fetch remote sub-resources.
/// * `policy` - The security policy configuration.
/// * `logger` - The logging interface.
/// * `rt_handle` - The Tokio runtime handle to block on async tasks.
/// * `output_dir` - The path to the directory where results are written.
///
/// # Returns
/// * None
fn process_file(
    path: PathBuf,
    index: usize,
    client: &SanitizerHttpClient,
    policy: &Policy,
    logger: &Logger,
    rt_handle: &tokio::runtime::Handle,
    output_dir: &PathBuf,
) {
    let output_path = output_dir.join(format!("{index}.html"));
    let sub_resources = Arc::new(Mutex::new(Vec::new()));

    let file_result = || -> Result<()> {
        let input_file = File::open(&path)
            .with_context(|| format!("Failed to open local file {:?}", path))?;
        let mut reader = BufReader::new(input_file);
        let output_file = File::create(&output_path)
            .with_context(|| format!("Failed to create output file {:?}", output_path))?;
        
        if policy.resources.fetch_sub_resources {
            let dummy_base = Arc::new(Mutex::new(Url::parse("https://localhost/").unwrap()));
            let mut rewriter = create_rewriter_with_crawler(
                logger,
                policy,
                dummy_base,
                Arc::clone(&sub_resources),
                output_file,
            );
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
        } else {
            let mut rewriter = create_rewriter(logger, policy, output_file);
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
        }
        Ok(())
    }();

    if let Err(error) = file_result {
        logger.log(LogLevel::Error, error);
        return;
    }

    // Crawl discovered sub-resources
    let discovered = {
        let guard = sub_resources.lock().unwrap();
        guard.clone()
    };

    if !discovered.is_empty() {
        let max_requests = policy.resources.max_requests;
        let max_bytes = policy.resources.max_bytes;
        let max_bytes_action = policy.resources.max_bytes_action;
        let max_depth = policy.resources.max_depth;

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut total_requests = 0;
        let mut total_bytes = 0;

        for (sub_url, local_name) in discovered {
            queue.push_back((sub_url, local_name, 1));
        }

        rt_handle.block_on(async {
            while let Some((url, local_name, depth)) = queue.pop_front() {
                if depth > max_depth {
                    continue;
                }
                if visited.contains(&url) {
                    continue;
                }
                if total_requests >= max_requests {
                    logger.warn(anyhow!("Sub-resource crawl limit reached: max_requests = {}", max_requests));
                    break;
                }

                total_requests += 1;
                let remaining_bytes = max_bytes.saturating_sub(total_bytes);
                if remaining_bytes == 0 {
                    let err = ContentTooLong(max_bytes);
                    let _ = max_bytes_action.handle_error(logger, err);
                    break;
                }

                logger.info(anyhow!("Crawling local file sub-resource (depth {}): {}", depth, url));

                let fetch_res = client.fetch_raw(&url, logger, policy, remaining_bytes).await;
                let fetched = match fetch_res {
                    Ok(f) => f,
                    Err(e) => {
                        logger.warn(anyhow!("Failed to fetch sub-resource {}: {}", url, e));
                        if total_bytes + remaining_bytes >= max_bytes {
                            let err = ContentTooLong(max_bytes);
                            let _ = max_bytes_action.handle_error(logger, err);
                        }
                        continue;
                    }
                };

                total_bytes += fetched.data.len();
                visited.insert(url.clone());

                let decl_type = fetched.content_type.as_deref();
                if let Err(mime_err) = validate_mime(decl_type, &fetched.data) {
                    logger.warn(anyhow!("MIME validation failed for {}: {}", url, mime_err));
                    continue;
                }

                use crate::sanitizer_engine::resource_sanitizer::{sniff_mime, strip_jpeg_metadata, strip_png_metadata, sanitize_css, sanitize_javascript};

                let sniffed = sniff_mime(&fetched.data).unwrap_or(decl_type.unwrap_or(""));
                let is_jpeg = sniffed == "image/jpeg" || url.path().ends_with(".jpg") || url.path().ends_with(".jpeg");
                let is_png = sniffed == "image/png" || url.path().ends_with(".png");
                let is_css = sniffed == "text/css" || url.path().ends_with(".css");
                let is_js = sniffed == "text/javascript" || sniffed == "application/javascript" || url.path().ends_with(".js");

                let sanitized_data = if is_jpeg {
                    strip_jpeg_metadata(&fetched.data)
                } else if is_png {
                    strip_png_metadata(&fetched.data)
                } else if is_css {
                    let css_str = String::from_utf8_lossy(&fetched.data);
                    let (sanitized_css, nested_urls) = sanitize_css(&css_str, &url);
                    if depth + 1 <= max_depth {
                        for (n_url, n_local) in nested_urls {
                            if !visited.contains(&n_url) {
                                queue.push_back((n_url, n_local, depth + 1));
                            }
                        }
                    }
                    sanitized_css.into_bytes()
                } else if is_js {
                    let js_str = String::from_utf8_lossy(&fetched.data);
                    match sanitize_javascript(&js_str) {
                        Ok(clean_js) => clean_js.into_bytes(),
                        Err(js_err) => {
                            logger.warn(anyhow!("JS validation failed for {}: {}", url, js_err));
                            b"/* Blocked by Web Sanitizer: dangerous keywords found */".to_vec()
                        }
                    }
                } else {
                    fetched.data.clone()
                };

                let sub_path = output_dir.join(&local_name);
                if let Err(e) = fs::write(&sub_path, &sanitized_data) {
                    logger.error(anyhow!("Failed to write sub-resource to {:?}: {}", sub_path, e));
                }
            }
        });
    }
}


/// Runs the main CLI application workflow: parses args, loads policy, submits jobs to the thread pool, and blocks until completion.
///
/// # Inputs
/// * None (inputs are gathered from command line arguments via `Args::parse()`).
///
/// # Returns
/// * `Result<()>` - `Ok(())` on successful completion, or an error if initialization fails.
pub async fn run() -> Result<()> {
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

    println!("Successfully created output directory: {:?}", args.output_dir);

    let client = Arc::new(SanitizerHttpClient::new(&policy).await?);
    let policy = Arc::new(policy);
    let max_size = (sources.len() as f64).log10().ceil() as usize;

    let pool = ThreadPool::new(args.workers); 
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

        pool.push_job(move || match source {
            InputSource::Url(url) => {
                process_url(url, i, &client, &policy, &logger, &rt_handle, &output_dir);
            }
            InputSource::File(path) => {
                process_file(path, i, &client, &policy, &logger, &rt_handle, &output_dir);
            }
        });
    });

    drop(pool); // This blocks until all jobs are executed

    Ok(())
}










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
