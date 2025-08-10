use duration_str::deserialize_duration;
use serde::{Deserialize, Deserializer};
use sqlx::sqlite::SqliteConnectOptions;
use std::{net::IpAddr, str::FromStr, time::Duration};

#[derive(serde::Deserialize, Debug)]
pub struct Configuration {
    /// The target address to forward requests to.
    pub target_host: Box<str>,
    /// The target port to forward requests at.
    pub target_port: u16,

    /// The address to listen for requests on.
    pub listen_on: IpAddr,
    /// The port to listen for requests on.
    pub listen_port: u16,

    #[serde(deserialize_with = "parse_sql_connection")]
    pub sqlite_db: SqliteConnectOptions,

    /// Name of the cookie used to verify a user.
    pub cookie_name: Box<str>,

    /// How long an authorsation token will be valid for.
    #[serde(deserialize_with = "deserialize_duration")]
    pub token_valid_for: Duration,
}

fn parse_sql_connection<'de, D>(data: D) -> Result<SqliteConnectOptions, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let string = String::deserialize(data)?;
    SqliteConnectOptions::from_str(&string).map_err(|err| D::Error::custom(format!("{err}")))
}

#[cfg(test)]
impl Configuration {
    pub fn test_config(options: SqliteConnectOptions) -> Self {
        Self {
            target_host: "http://example.com".into(),
            target_port: 80,
            listen_on: [0, 0, 0, 0].into(),
            listen_port: 80,
            sqlite_db: options,
            cookie_name: "id".into(),
            token_valid_for: Duration::from_secs(60 * 60),
        }
    }
}

#[cfg(test)]
mod tests {
    use config::Config;

    use super::*;

    #[test]
    fn parse_example() {
        let config: Configuration = Config::builder()
            .add_source(config::File::with_name("./configuration.toml"))
            .build()
            .and_then(Config::try_deserialize)
            .unwrap();
    }
}
