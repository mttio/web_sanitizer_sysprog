/*
The tool must accept one or more inputs
local HTML/asset files, a directory tree, or a list of URLs to fetch
*/

use crate::cli_application::http_client::fetch_multiple_urls;
use crate::sanitizer_engine::engine_structs::InputSource;
use crate::sanitizer_engine::errors::{DangerousDomain, IDN, error};
use crate::sanitizer_engine::policy::Policy;
use crate::sanitizer_engine::url::{RuleMatch, check_domain};
use anyhow::{Context, Result};
use clap::Parser;
use lol_html::{HtmlRewriter, Settings, element};
use serde_json;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
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

    println!("Successfully loaded policy: {policy:#?}");

    // Prepare inputs
    let mut sources = Vec::new();

    for input in args.inputs {
        // Try to parse as URL first
        if let Ok(url) = Url::parse(&input)
            && (url.scheme() == "http" || url.scheme() == "https")
        {
            {
                if let Some(original) = check_domain(&url)
                    && let Err(e) = policy.urls.idn_action.handle_error(IDN(original))
                {
                    error(e);
                    continue;
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
                        .handle_error(DangerousDomain(host.to_owned()))
                {
                    error(e);
                    continue;
                }
            }

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

    println!("Successfully created input sources vector: {:?}", sources);

    let result = fetch_multiple_urls(sources, &policy).await.unwrap();

    for (i, data) in result.0.into_iter().enumerate() {
        // let input = client.execute(client.get(url).build()?).await?;

        let mut output = File::create(format!("./output/{i}.html"))?;

        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![element!("a[href], link[href]", |el| {
                    let href = el.get_attribute("href").expect("href was required");
                    if let Ok(mut href) = Url::parse(&href)
                        && let Some(host) = href.host()
                    {
                        let host = host.to_owned();
                        let is_dangerous = policy
                            .urls
                            .dangerous_domains
                            .iter()
                            .any(|x| x.0.matches(&host));

                        if is_dangerous {
                            let result = policy.html.dangerous_domain_action.handle_error_with(
                                || -> Result<_, Box<dyn Error>> {
                                    href.set_host(Some("example.com"))?;
                                    el.set_attribute("href", href.as_ref())?;
                                    Ok(())
                                },
                                DangerousDomain(host.to_owned()),
                            );

                            match result {
                                Err(e) => error(e),
                                Ok(Some(Err(e))) => error(e),
                                _ => {}
                            }
                        }
                    }

                    Ok(())
                })],
                ..Settings::new()
            },
            |c: &[u8]| {
                // println!("{}\n", str::from_utf8(c).unwrap());
                output.write_all(c).unwrap();
            },
        );

        /* {
            use futures_util::StreamExt;
            let mut input = input.bytes_stream();

            while let Some(chunk) = input.next().await {
                let chunk = chunk?;
                rewriter.write(&chunk)?;
            }
        } */

        rewriter.write(&data.data)?;
        rewriter.end()?;
    }

    for error in result.1 {
        crate::sanitizer_engine::errors::error(error);
    }

    //Now for each source in sources we need to:
    //   if is FILE
    //       if is HTML
    //           sanitize html
    //       if is Asset
    //           sanitize asset
    //   if is URL
    //       fetch it safely
    //       if is HTML
    //           sanitize html
    //       if is Asset
    //           sanitize asset

    // Ensure output directory exists
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {:?}", args.output_dir))?;

    println!(
        "Successfully created output directory: {:?}",
        args.output_dir
    );

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
