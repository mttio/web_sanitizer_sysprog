use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

// This will now compile perfectly!
#[derive(Debug, Serialize, Deserialize)]
pub enum InputSource {
    File(PathBuf),
    Url(Url),
}
