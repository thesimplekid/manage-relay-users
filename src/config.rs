//! Configuration file and settings management
use config::{Config, ConfigError, File};
use log::warn;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Info {
    pub admin_keys: Vec<String>,
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Settings {
    pub info: Info,
}

impl Settings {
    #[must_use]
    pub fn new(config_file_name: &Option<String>) -> Self {
        let default_settings = Self::default();
        // attempt to construct settings with file
        let from_file = Self::new_from_default(&default_settings, config_file_name);
        match from_file {
            Ok(f) => f,
            Err(e) => {
                warn!("Error reading config file ({:?})", e);
                default_settings
            }
        }
    }

    fn new_from_default(
        default: &Settings,
        config_file_name: &Option<String>,
    ) -> Result<Self, ConfigError> {
        let default_config_file_name = "config.toml".to_string();
        let config: &String = match config_file_name {
            Some(value) => value,
            None => &default_config_file_name,
        };
        let builder = Config::builder();
        let config: Config = builder
            // use defaults
            .add_source(Config::try_from(default)?)
            // override with file contents
            .add_source(File::with_name(config))
            .build()?;
        let settings: Settings = config.try_deserialize()?;

        // println!("{settings:?}");

        Ok(settings)
    }
}
