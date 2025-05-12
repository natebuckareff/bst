use anyhow::{Result, anyhow};

use crate::{
    crypto::IdentitySecretKey, local_config::LocalConfig, text_table::TextTable,
    util::format_duration,
};

const DEFAULT_IDENTITY_NAME: &'static str = "identity";

pub struct App {
    local_config: LocalConfig,
}

impl App {
    pub fn new(local_config: LocalConfig) -> Self {
        Self { local_config }
    }

    pub fn handle_list_identities(&self) -> Result<()> {
        let mut table = TextTable::build()
            .add_colum("name")
            .add_colum("created")
            .add_colum("public key")
            .done();

        let mut identities = self
            .local_config
            .get_identities()
            .iter()
            .collect::<Vec<_>>();
        identities.sort_by_key(|(_, (created_at, _))| created_at);

        for (name, (created_at, identity)) in identities {
            let created_at = format_duration(created_at.elapsed()?);
            table.push(name.clone());
            table.push(format!("{created_at} ago"));
            table.push(identity.get_public_key().as_string());
        }

        table.print();

        Ok(())
    }

    pub fn handle_generate_identity(&mut self, name: Option<String>) -> Result<()> {
        let mut is_default = false;
        let name = name.unwrap_or_else(|| {
            is_default = true;
            String::from(DEFAULT_IDENTITY_NAME)
        });

        let identity = IdentitySecretKey::generate()?;
        let public_key = identity.get_public_key();
        let added = self
            .local_config
            .add_and_write_identity(name.clone(), identity)?;

        if !added {
            return Err(anyhow!(
                "identity with the name \"{}\" already exists",
                name
            ));
        }

        dbg!(is_default);
        if is_default {
            if let None = self.local_config.get_config_default_identity() {
                let public_key = public_key.clone();
                self.local_config.set_config_default_identity(public_key);
                self.local_config.write_config_file()?;
            }
        }

        println!("{}", public_key.as_string());

        Ok(())
    }

    pub fn handle_derive_public_key(&self, name: String) -> Result<()> {
        let identities = self.local_config.get_identities();
        match identities.get(&name) {
            Some((_, identity)) => {
                let public_key = identity.get_public_key();
                println!("{}", public_key.as_string());
                Ok(())
            }
            None => Err(anyhow!("identity not found")),
        }
    }
}
