use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Serialize, Deserialize)]
pub enum InputSource {
    File(PathBuf),
    Url(Url),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchedContent {
    pub source: InputSource,
    pub data: Vec<u8>,
    pub content_type: Option<String>,
}
