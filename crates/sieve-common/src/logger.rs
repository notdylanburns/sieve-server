use log::{error, warn};

pub type LogLevel = log::LevelFilter;

#[derive(Debug, Clone, Copy)]
pub struct LogConfig {
    pub id: &'static str,
    pub level: LogLevel,
}

// Logs go to stderr: stdout is the squid helper protocol channel, and docker captures both.
pub fn init(config: LogConfig) -> Result<(), log::SetLoggerError> {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|level| level.parse().ok())
        .unwrap_or(config.level);

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} {}[{}] {} {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                config.id,
                std::process::id(),
                record.level(),
                message,
            ))
        })
        .level(level)
        .chain(std::io::stderr())
        .apply()
}

pub trait LogError {
    fn log_warning(self, msg: &str) -> Self;
    fn log_error(self, msg: &str) -> Self;
}

impl<T, E: std::fmt::Display> LogError for Result<T, E> {
    fn log_error(self, msg: &str) -> Self {
        self.inspect_err(|e| error!("{msg}: {e}"))
    }

    fn log_warning(self, msg: &str) -> Self {
        self.inspect_err(|e| warn!("{msg}: {e}"))
    }
}

impl<T> LogError for Option<T> {
    fn log_error(self, msg: &str) -> Self {
        self.or_else(|| {
            error!("{msg}");
            None
        })
    }

    fn log_warning(self, msg: &str) -> Self {
        self.or_else(|| {
            warn!("{msg}");
            None
        })
    }
}
