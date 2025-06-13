use serde::Deserialize;

pub mod harvester;

#[derive(Debug, Deserialize)]
pub struct Sources {
    pub free_proxy_list: Option<String>,
    pub ssl_proxies: Option<String>,
    pub proxy_scrape: Option<Vec<String>>,
    pub github_lists: Option<Vec<String>>,
    pub proxybroker_cmd: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub sources: Sources,
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name(path))
            .build()?
            .try_deserialize()
    }
}
