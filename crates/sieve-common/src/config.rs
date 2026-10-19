use std::path::PathBuf;

pub const METADATA_REFRESH_INTERVAL: i64 = 60 * 60 * 24 * 30;
pub const METADATA_RETRY_INTERVAL: i64 = 60 * 60 * 24;

#[derive(Debug)]
pub enum Error {
    Missing(&'static str),
    Invalid(&'static str, String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "environment variable {name} is not set"),
            Self::Invalid(name, reason) => write!(f, "environment variable {name} is invalid: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

pub fn var(name: &'static str) -> Result<String, Error> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) | Err(std::env::VarError::NotPresent) => Err(Error::Missing(name)),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(Error::Invalid(name, "not valid unicode".into()))
        }
    }
}

pub fn var_or(name: &'static str, default: &str) -> Result<String, Error> {
    match var(name) {
        Err(Error::Missing(_)) => Ok(default.into()),
        result => result,
    }
}

pub fn parse_var<T>(name: &'static str) -> Result<T, Error>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    var(name)?
        .parse()
        .map_err(|e: T::Err| Error::Invalid(name, e.to_string()))
}

pub fn parse_var_or<T>(name: &'static str, default: &str) -> Result<T, Error>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    var_or(name, default)?
        .parse()
        .map_err(|e: T::Err| Error::Invalid(name, e.to_string()))
}

pub fn database_url() -> Result<String, Error> {
    var("DATABASE_URL")
}

pub fn icon_dir() -> Result<PathBuf, Error> {
    var("ICON_DIR").map(PathBuf::from)
}
