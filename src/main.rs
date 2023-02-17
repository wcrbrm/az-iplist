mod args {
    use clap::{Parser, Subcommand};

    #[derive(Subcommand, Debug)]
    pub enum CliCommand {
        /// search for existing IP addresses in security group rules
        List,
        /// add IP address to all known white lists
        Add { ip: String },
        /// remove IP address from all known white lists
        Remove { ip: String },
    }

    /// AZ-WHITELIST: manages white lists of IP addresses for all Azure resources
    #[derive(Parser, Debug)]
    #[command(author, version, about, long_about = None)]
    pub struct Cli {
        #[command(subcommand)]
        pub command: CliCommand,
    }
}

mod logging {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    pub fn start() {
        let is_terminal = atty::is(atty::Stream::Stdout);
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or(EnvFilter::new("INFO,ureq=WARN,az_whitelist=INFO"));
        let subscriber = tracing_subscriber::fmt::fmt()
            .with_env_filter(env_filter)
            .with_ansi(is_terminal)
            .with_span_events(fmt::format::FmtSpan::CLOSE) // enable durations
            .finish();
        _ = subscriber.with(ErrorLayer::default()).try_init();
    }
}

mod access {
    use anyhow::Context;
    use serde::{Deserialize, Serialize};
    use std::process::Command;
    use tracing::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AccessTokenInfo {
        pub access_token: String,
    }

    #[instrument(level = "DEBUG")]
    pub fn get_token() -> anyhow::Result<String> {
        let output = Command::new("az")
            .arg("account")
            .arg("get-access-token")
            .output()
            .expect("failed to execute process");

        if let Some(exit_code) = output.status.code() {
            if exit_code == 0 {
                let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
                let info: AccessTokenInfo = serde_json::from_str(&stdout_str).context("parse")?;
                return Ok(info.access_token.clone());
            } else {
                debug!("exit code: {}", exit_code);
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                return Err(anyhow::Error::msg(stderr));
            }
        }
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(anyhow::Error::msg(stderr));
    }
}

pub mod resource {
    use anyhow::Context;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::process::Command;
    use std::time::Duration;
    use tracing::*;
    use ureq::{Agent, AgentBuilder};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Identified {
        id: String,
        #[serde(rename = "type")]
        resource_type: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Resource<T> {
        pub name: String,
        pub id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub etag: Option<String>,
        #[serde(rename = "type")]
        pub resource_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub properties: Option<T>,
    }

    #[derive(Debug, Clone)]
    pub enum ResourceType {
        DiskAccesses,
        Disks,
        Snapshots,
        SshPublicKeys,
        VirtualMachines,
        Registries,
        ManagedClusters,
        NetworkInterfaces,
        NetworkSecurityGroups,
        PublicIpAddresses,
        VirtualNetworks,
    }

    impl ResourceType {
        pub fn to_str(&self) -> &'static str {
            match self {
                Self::DiskAccesses => "Microsoft.Compute/diskAccesses",
                Self::Disks => "Microsoft.Compute/disks",
                Self::Snapshots => "Microsoft.Compute/snapshots",
                Self::SshPublicKeys => "Microsoft.Compute/sshPublicKeys",
                Self::VirtualMachines => "Microsoft.Compute/virtualMachines",
                Self::Registries => "Microsoft.ContainerRegistry/registries",
                Self::ManagedClusters => "Microsoft.ContainerService/managedClusters",
                Self::NetworkInterfaces => "Microsoft.Network/networkInterfaces",
                Self::NetworkSecurityGroups => "Microsoft.Network/networkSecurityGroups",
                Self::PublicIpAddresses => "Microsoft.Network/publicIPAddresses",
                Self::VirtualNetworks => "Microsoft.Network/virtualNetworks",
            }
        }
    }

    #[instrument(level = "DEBUG")]
    pub fn list_ids(resource_type: Option<ResourceType>) -> anyhow::Result<Vec<String>> {
        let output = Command::new("az")
            .arg("resource")
            .arg("list")
            .output()
            .expect("failed to execute process");

        if let Some(exit_code) = output.status.code() {
            if exit_code == 0 {
                let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
                let list: Vec<Resource<Identified>> =
                    serde_json::from_str(&stdout_str).context("parse")?;
                let ids: Vec<String> = list
                    .iter()
                    .filter(|r| match &resource_type {
                        Some(restricted) => *restricted.to_str() == r.resource_type,
                        None => true,
                    })
                    .map(|r| (r.id.clone()))
                    .collect();
                return Ok(ids);
            } else {
                debug!("exit code: {}", exit_code);
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                return Err(anyhow::Error::msg(stderr));
            }
        }
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(anyhow::Error::msg(stderr));
    }

    #[instrument(level = "DEBUG", skip(access_token))]
    pub fn get<T>(access_token: &str, resource_id: &str) -> anyhow::Result<Resource<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!(
            "https://management.azure.com{}?api-version=2022-09-01",
            resource_id
        );
        let auth_header = format!("Bearer {}", access_token);
        let agent: Agent = AgentBuilder::new()
            .timeout_read(Duration::from_secs(25))
            .build();
        let response: Resource<T> = agent
            .get(&url)
            .set("Content-Type", "application/json")
            .set("Authorization", &auth_header)
            .call()
            .context("get resource")?
            .into_json()
            .context("parse resource")?;
        Ok(response)
    }

    #[instrument(level = "INFO", skip(access_token, doc))]
    pub fn put<T>(access_token: &str, doc: Resource<T>) -> anyhow::Result<Value>
    where
        T: serde::ser::Serialize,
    {
        let url = format!(
            "https://management.azure.com{}?api-version=2022-09-01",
            doc.id
        );
        let auth_header = format!("Bearer {}", access_token);
        let agent: Agent = AgentBuilder::new()
            .timeout_read(Duration::from_secs(25))
            .build();
        let payload = serde_json::to_string(&doc).context("serialize")?;
        let response: Value = agent
            .put(&url)
            .set("Content-Type", "application/json")
            .set("Authorization", &auth_header)
            .send_string(&payload)
            .context("put resource")?
            .into_json()
            .context("parse response")?;
        Ok(response)
    }
}

// network securty groups definition
mod nsg {
    use crate::resource::Resource;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Rule {
        pub access: String,
        pub destination_address_prefix: Option<String>,
        pub destination_address_prefixes: Option<Vec<String>>,
        pub destination_port_range: Option<String>,
        pub destination_port_ranges: Option<Vec<String>>,
        pub direction: String,
        pub priority: i32,
        pub protocol: String,
        pub provisioning_state: String,
        pub source_address_prefix: Option<String>,
        pub source_address_prefixes: Option<Vec<String>>,
        pub source_port_range: Option<String>,
        pub source_port_ranges: Option<Vec<String>>,
    }

    impl Rule {
        /// returns list of addresses, if any
        pub fn lists(&self) -> Option<Vec<String>> {
            if let Some(addresses) = &self.source_address_prefixes {
                if addresses.len() > 0 {
                    return Some(addresses.clone());
                }
            }
            None
        }
        /// add given IP, returns if anything was modified
        pub fn add_ip(&mut self, ip_address: &str) -> bool {
            if let Some(addresses) = &mut self.source_address_prefixes {
                for address in addresses.iter() {
                    if address == ip_address {
                        return false; // it was already there, nothing to change
                    }
                }
                addresses.push(ip_address.to_string());
                return true;
            }
            false // nothiing changed
        }

        /// delete given IP, returns if anything was modified
        pub fn remove_ip(&mut self, ip_address: &str) -> bool {
            if let Some(addresses) = &mut self.source_address_prefixes {
                if let Some(index) = addresses.iter().position(|x| x == ip_address) {
                    addresses.remove(index);
                    return true;
                }
            }
            false // nothing changed
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkInterface {
        pub id: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SecurityGroup {
        pub provisioning_state: String,
        pub resource_guid: String,
        pub security_rules: Vec<Resource<Rule>>,
        pub default_security_rules: Vec<Resource<Rule>>,
        pub network_interfaces: Option<Vec<NetworkInterface>>,
    }

    impl SecurityGroup {
        pub fn get_whitelist_rules(&self) -> Vec<Resource<Rule>> {
            let mut out = vec![];
            for res in &self.security_rules {
                if let Some(rule) = &res.properties {
                    if let Some(_) = rule.lists() {
                        out.push(res.clone());
                    }
                }
            }
            out
        }
    }
}

use clap::Parser;
use tracing::*;

fn main() {
    logging::start();
    color_eyre::install().unwrap();

    let cli = args::Cli::parse();

    let t = resource::ResourceType::NetworkSecurityGroups; // listing all security groups
    let access_token = access::get_token().unwrap(); // getting access
    let list_nsg: Vec<String> = resource::list_ids(Some(t)).unwrap();

    match &cli.command {
        args::CliCommand::Add { ip } => {
            for id in list_nsg {
                let nsg = resource::get::<nsg::SecurityGroup>(&access_token, &id).unwrap();
                let sg = nsg.properties.unwrap();
                debug!(
                    "found {} rules in security group {}",
                    sg.security_rules.len(),
                    nsg.id,
                );
                for res_rule in sg.get_whitelist_rules() {
                    let mut res = res_rule.clone();
                    if let Some(rule) = &mut res.properties {
                        info!("{:?} {:?}", rule.source_address_prefixes, res_rule.id);
                        if rule.add_ip(&ip) {
                            resource::put(&access_token, res).unwrap();
                        }
                    }
                }
            }
        }
        args::CliCommand::Remove { ip } => {
            for id in list_nsg {
                let nsg = resource::get::<nsg::SecurityGroup>(&access_token, &id).unwrap();
                let sg = nsg.properties.unwrap();
                debug!(
                    "found {} rules in security group {}",
                    sg.security_rules.len(),
                    nsg.id,
                );
                for res_rule in sg.get_whitelist_rules() {
                    let mut res = res_rule.clone();
                    if let Some(rule) = &mut res.properties {
                        info!("{:?} {:?}", rule.source_address_prefixes, res_rule.id);
                        if rule.remove_ip(&ip) {
                            resource::put(&access_token, res).unwrap();
                        }
                    }
                }
            }
        }
        args::CliCommand::List => {
            for id in list_nsg {
                let nsg = resource::get::<nsg::SecurityGroup>(&access_token, &id).unwrap();
                let sg = nsg.properties.unwrap();
                debug!(
                    "found {} rules in security group {}",
                    sg.security_rules.len(),
                    nsg.id,
                );
                for res_rule in sg.get_whitelist_rules() {
                    info!("{:?}", res_rule);
                }
            }
        }
    }
}
