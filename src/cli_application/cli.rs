/*
The tool must accept one or more inputs  
local HTML/asset files, a directory tree, or a list of URLs to fetch
*/

use std::path::{Path, PathBuf};
use std::fs;
use clap::Parser;
use crate::sanitizer_engine::engine_structs::InputSource;
use crate::sanitizer_engine::policy::Policy;
use anyhow::{Context, Result};
use url::Url;
use walkdir::WalkDir;
use serde_json;





#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Input files, directories or URLs
    #[arg(required = true, num_args = 1..)]
    pub inputs: Vec<String>,

    /// Policy configuration file (JSON)
    #[arg(short, long, default_value = "default_policy.json")]
    pub policy: PathBuf,

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
    let base_policy_path = Path::new("policies");
    let content = fs::read_to_string(base_policy_path.join(&args.policy))
            .with_context(|| format!("Failed to read policy file: {:?}", &args.policy))?;
    let policy: Policy = serde_json::from_str(&content).context("Failed to parse policy file")?;
    
    println!("Successfully loaded policy: {:?}", policy);




    // Prepare inputs
    let mut sources = Vec::new();

    for input in args.inputs {
        // Try to parse as URL first
        if let Ok(url) = Url::parse(&input) {
            if url.scheme() == "http" || url.scheme() == "https" {
                println!("Input '{}' recognized as URL", input);
                sources.push(InputSource::Url(url));
                continue;
            }
        }

        let path = PathBuf::from(&input);
        if path.is_dir() {
            println!("Input '{}' recognized as Directory", input);
            // Explore directory recursively
            for entry in WalkDir::new(&path) {
                let entry = entry.with_context(|| format!("Failed to read directory entry in {:?}", path))?;
                if entry.file_type().is_file() && !is_hidden(&entry) {
                    sources.push(InputSource::File(entry.path().to_path_buf()));
                }
            }
        } else if path.is_file() {
            println!("Input '{}' recognized as File", input);
            sources.push(InputSource::File(path));
        } else {
            println!("Warning: Input '{}' not found or not a supported URL scheme. Skipping.", input);
        }
    }

    // No-sources case
    if sources.is_empty() {
        println!("No valid inputs provided.");
        return Ok(());
    }

    println!("Successfully created input sources vector: {:?}", sources);




    //Now for each source in sources we need to:
    //   if is FILE
                //if is HTML
                    //sanitize html
                //if is Asset
                    //sanitize asset

    //   if is URL
            //fetch it safely
                    //if is HTML
                            //sanitize html
                    //if is Asset
                            //sanitize asset






    // Ensure output directory exists
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {:?}", args.output_dir))?;

    println!("Successfully created output directory: {:?}", args.output_dir);



    Ok(())
}



/*======================== HELPERS ============================*/

fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry.file_name()
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
        let args = Args::try_parse_from(&["test", "input1.html"]).unwrap();
        assert_eq!(args.inputs, vec!["input1.html"]);
        assert_eq!(args.policy, PathBuf::from("default_policy.json"));
        assert_eq!(args.output_dir, PathBuf::from("output"));
        assert_eq!(args.workers, 4);
        assert!(!args.verbose);
    }

    #[test]
    fn test_multiple_inputs() {
        let args = Args::try_parse_from(&["test", "input1.html", "input2.html", "http://example.com"]).unwrap();
        assert_eq!(args.inputs, vec!["input1.html", "input2.html", "http://example.com"]);
    }

    #[test]
    fn test_custom_flags() {
        let args = Args::try_parse_from(&[
            "test",
            "input.html",
            "--policy", "custom_policy.json",
            "--output-dir", "custom_output",
            "--workers", "8",
            "--verbose"
        ]).unwrap();
        assert_eq!(args.policy, PathBuf::from("custom_policy.json"));
        assert_eq!(args.output_dir, PathBuf::from("custom_output"));
        assert_eq!(args.workers, 8);
        assert!(args.verbose);
    }

    #[test]
    fn test_missing_input_fails() {
        let result = Args::try_parse_from(&["test"]);
        assert!(result.is_err());
    }
}
