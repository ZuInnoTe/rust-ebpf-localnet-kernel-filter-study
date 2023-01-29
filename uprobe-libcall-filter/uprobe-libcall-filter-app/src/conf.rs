//! Simple configuration file manager

use serde::{Deserialize, Serialize};
use serde_yaml;
use std::collections::HashMap;

/// Definition of an application
#[derive(Deserialize, Serialize)]
pub struct Configuration {
    pub applications: HashMap<String, HashMap<String, ApplicationDefinition>>,
}

/// General properties of an application
#[derive(Deserialize, Serialize)]
pub struct ApplicationDefinition {
    pub openssl_lib: String
}

/// Load configuration for the filter
///
/// # Arguments
/// * `path` - path to configuration file
///
/// Returns an option with the configuration  [`Configuration`] or an error ([`std::error::Error`]). Fails if the file cannot be loaded at all
///
pub fn load_config(path: String) -> Result<Configuration, Box<dyn std::error::Error>> {
    let f = std::fs::File::open(&path).expect(&format!("Cannot open file: {}", &path));
    match serde_yaml::from_reader(f) {
        Ok(conf) => Ok(conf),
        Err(err) => Err(Box::new(err)),
    }
}
