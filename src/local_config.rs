use std::{
    collections::HashMap, fs, io::Write, os::unix::fs::PermissionsExt, path::PathBuf,
    time::SystemTime,
};

use anyhow::{Result, anyhow, bail};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::crypto::{IdentityPublicKey, IdentitySecretKey};

const PROJECT_QUALIFIER: &'static str = "xyz";
const PROJECT_ORGANIZATION: &'static str = "nateb";
const PROJECT_APP: &'static str = "bst";

#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    pub defaults: Option<ConfigFileDefaults>,
    pub repositories: HashMap<String, ConfigRepository>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            defaults: None,
            repositories: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConfigFileDefaults {
    pub identity: Option<IdentityPublicKey>,
    pub repository: Option<ConfigRepository>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigRepository {
    pub url: Option<Url>,
    pub path: Option<PathBuf>,
    pub public_key: Option<IdentityPublicKey>,
}

pub struct LocalConfig {
    config_file: ConfigFile,
    identities: HashMap<String, (SystemTime, IdentitySecretKey)>,
}

impl LocalConfig {
    pub fn new() -> Result<Self> {
        let config_dir_path = match Self::get_config_dir_path()? {
            (config_path, true) => config_path,
            (_, false) => return Ok(LocalConfig::default()),
        };

        let (config_file_path, exists) = Self::get_config_file_path()?;
        let config_file = if exists {
            let config_file_text = fs::read_to_string(config_file_path)?;
            toml::from_str(&config_file_text)?
        } else {
            ConfigFile::default()
        };

        let mut identities = HashMap::new();
        let dir = fs::read_dir(config_dir_path)?;
        for entry in dir {
            let entry = entry?;
            let created_at = entry.metadata()?.created()?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if file_name.ends_with(".skey") {
                let name = String::from(&file_name[0..file_name.len() - 5]);
                let identity_text = fs::read_to_string(entry.path())?;
                let identity_text = identity_text.trim();
                let identity = IdentitySecretKey::from_str(identity_text)?;
                identities.insert(name, (created_at, identity));
            }
        }

        Ok(Self {
            config_file,
            identities,
        })
    }

    fn get_config_dir_path() -> Result<(PathBuf, bool)> {
        let project_dirs = ProjectDirs::from(PROJECT_QUALIFIER, PROJECT_ORGANIZATION, PROJECT_APP)
            .ok_or(anyhow::anyhow!("failed to get project directories"))?;

        let config_dir_path = project_dirs.config_local_dir();
        if config_dir_path.exists() {
            if !config_dir_path.is_dir() {
                bail!("invalid config directory");
            }
        } else {
            return Ok((config_dir_path.into(), false));
        }

        Ok((config_dir_path.into(), true))
    }

    fn get_config_file_path() -> Result<(PathBuf, bool)> {
        let (config_dir_path, exists) = Self::get_config_dir_path()?;
        let config_file_path = config_dir_path.join("config.toml");
        if config_file_path.exists() {
            if !config_file_path.is_file() {
                Err(anyhow!("invalid config file"))
            } else {
                Ok((config_file_path, true))
            }
        } else {
            Ok((config_file_path, false))
        }
    }

    fn get_or_create_config_dir_path() -> Result<PathBuf> {
        match Self::get_config_dir_path()? {
            (config_dir_path, true) => Ok(config_dir_path),
            (config_dir_path, false) => {
                fs::create_dir_all(&config_dir_path)?;
                Ok(config_dir_path)
            }
        }
    }

    pub fn get_config_file(&self) -> &ConfigFile {
        &self.config_file
    }

    pub fn get_mut_config_file(&mut self) -> &mut ConfigFile {
        &mut self.config_file
    }

    pub fn get_config_default_identity(&self) -> Option<&IdentityPublicKey> {
        match &self.config_file.defaults {
            Some(defaults) => defaults.identity.as_ref(),
            None => None,
        }
    }

    pub fn set_config_default_identity(&mut self, identity: IdentityPublicKey) {
        match &mut self.config_file.defaults {
            Some(defaults) => {
                defaults.identity = Some(identity);
            }
            None => {
                self.config_file.defaults = Some(ConfigFileDefaults {
                    identity: Some(identity),
                    repository: None,
                })
            }
        };
    }

    pub fn get_identities(&self) -> &HashMap<String, (SystemTime, IdentitySecretKey)> {
        &self.identities
    }

    pub fn write_config_file(&self) -> Result<()> {
        let config_file_path = Self::get_or_create_config_dir_path()?.join("config.toml");
        let config_file_text = toml::to_string(&self.config_file)?;
        fs::write(config_file_path, config_file_text)?;
        Ok(())
    }

    pub fn add_and_write_identity(
        &mut self,
        name: String,
        identity: IdentitySecretKey,
    ) -> Result<bool> {
        if self.identities.contains_key(&name) {
            return Ok(false);
        }
        let identity_text = identity.to_string() + "\n";
        let identity_file_name = name.clone() + ".skey";
        let identity_path = Self::get_or_create_config_dir_path()?.join(identity_file_name);

        let mut file = fs::File::create(identity_path)?;
        let metadata = file.metadata()?;

        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);

        file.set_permissions(permissions)?;
        file.write_all(identity_text.as_bytes())?;

        let now = SystemTime::now();
        self.identities.insert(name, (now, identity));
        Ok(true)
    }
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            config_file: ConfigFile::default(),
            identities: HashMap::new(),
        }
    }
}
