use std::{
    path::PathBuf,
    sync::{Arc, mpsc::Sender},
};

use futures_util::future::lazy;
use parking_lot::Mutex;
use tokio::runtime::Runtime;

use crate::{
    crawl_session::CrawlSession,
    engine_structs::InputSource,
    errors::SanitizerError,
    http_client::SanitizerHttpClient,
    log::{ChannelLogger, LoggerMessage},
    policy::Policy,
};

pub mod crawl_session;
pub mod engine_structs;
pub mod errors;
pub mod html;
pub mod http_client;
pub mod log;
pub mod policy;
pub mod resources;
pub mod rules;
pub mod url;

pub fn library(
    runtime: &Runtime,
    sources: Vec<InputSource>,
    policy: Arc<Policy>,
    output_dir: Arc<PathBuf>,
    tx: Sender<LoggerMessage>,
) -> Result<(), SanitizerError> {
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

    let client = Arc::new(SanitizerHttpClient::new(
        policy.clone(),
        tx.clone(),
        url_map.clone(),
    )?);

    for (i, source) in sources.into_iter().enumerate() {
        let logger = ChannelLogger {
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

    drop(client);

    Ok(())
}
