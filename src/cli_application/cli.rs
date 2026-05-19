/*
The tool must accept one or more inputs  
local HTML/asset files, a directory tree, or a list of URLs to fetch
*/

use std::path::{Path, PathBuf};
use std::fs;
use clap::Parser;
use anyhow::{Context, Result};
use url::Url;
use walkdir::WalkDir;
use serde_json;
use crate::sanitizer_engine::engine_structs::{InputSource, Policy};





#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Input files or directories
    #[arg(short, long)]
    pub inputs: Vec<String>,

    /// URL inputs
    #[arg(short, long)]
    pub urls: Vec<String>,

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
    let base_policy_path = Path::new("/policies");
    let content = fs::read_to_string(base_policy_path.join(&args.policy))
            .with_context(|| format!("Failed to read policy file: {:?}", &args.policy))?;
    let policy: Policy = serde_json::from_str(&content).context("Failed to parse policy file")?;
    
    println!("Successfully loaded policy: {:?}", policy);




    // Prepare inputs
    let mut sources = Vec::new();

    //take care of file and folder inputs
    for input in args.inputs {
        let path = PathBuf::from(&input);

        if path.is_dir() //DIRECTORY
        {
            // Explore directory recursively
            for entry in WalkDir::new(path) {
                let entry = entry.context("Failed to read directory entry")?;
                if entry.file_type().is_file() {
                    sources.push(InputSource::File(entry.path().to_path_buf()));
                };
            }
        }
        else //SINGLE FILE
        {
            sources.push(InputSource::File(path));
        };
    };


    //add URLs to input sources as well
    for url_str in args.urls {
        let url = Url::parse(&url_str).context(format!("Invalid URL: {}", url_str))?;
        sources.push(InputSource::Url(url));
    }







    //No-sources case
    if sources.is_empty() {
        println!("No inputs provided.");
        return Ok(());
    }

    println!("Successfully created input sources vector: {:?}", sources);






    // Ensure output directory exists
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {:?}", args.output_dir))?;

    println!("Successfully created output directory: {:?}", args.output_dir);



    Ok(())
}
