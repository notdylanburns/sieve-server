use std::future::Future;
use std::process::ExitCode;

use log::{error, warn};
use percent_encoding::percent_decode_str;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Squid's helper protocol: one request per line on stdin, one reply per line on stdout.
/// Runs until Squid closes stdin.
pub async fn serve<F, Fut>(mut handle: F) -> ExitCode
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = &'static str>,
{
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                warn!("stdin closed, shutting down");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                error!("failed to read stdin: {e}");
                return ExitCode::FAILURE;
            }
        };

        let reply = handle(line).await;

        let written = stdout.write_all(format!("{reply}\n").as_bytes()).await;
        if let Err(e) = written.and(stdout.flush().await) {
            error!("failed to write stdout: {e}");
            return ExitCode::FAILURE;
        }
    }
}

/// Squid URL-escapes helper fields and sends `-` for a missing value.
pub fn field(raw: &str) -> Option<Box<str>> {
    if raw == "-" {
        return None;
    }
    Some(percent_decode_str(raw).decode_utf8_lossy().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_unescaped_and_dash_is_missing() {
        assert_eq!(field("-"), None);
        assert_eq!(field("dev-abc").as_deref(), Some("dev-abc"));
        assert_eq!(field("p%20a%2Bss+word").as_deref(), Some("p a+ss+word"));
    }
}
