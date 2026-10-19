use std::process::ExitCode;

use log::error;
use sieve_common::{database, logger};

use crate::update::Scope;

mod fetch;
mod icon;
mod service;
mod update;
mod video;

const USAGE: &str = "usage: sieve-metadata-cache run
       sieve-metadata-cache update [--force]
       sieve-metadata-cache inspect <url> [output.png]";

enum Command<'a> {
    Run,
    Update { force: bool },
    Inspect { url: &'a str, output: &'a str },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let command = match args.as_slice() {
        ["run"] => Command::Run,
        ["update"] => Command::Update { force: false },
        ["update", "--force"] => Command::Update { force: true },
        ["inspect", url] => Command::Inspect {
            url,
            output: "icon.png",
        },
        ["inspect", url, output] => Command::Inspect { url, output },
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let log_config = logger::LogConfig {
        id: "sieve-metadata-cache",
        level: logger::LogLevel::Info,
    };

    if let Err(e) = logger::init(log_config) {
        eprintln!("error: failed to configure logger: {e}");
        return ExitCode::FAILURE;
    }

    let client = match fetch::client() {
        Ok(client) => client,
        Err(e) => {
            error!("failed to create http client: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Command::Inspect { url, output } = command {
        return match inspect(&client, url, output).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!("{e}");
                ExitCode::FAILURE
            }
        };
    }

    let config = match update::Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };

    // One connection for passes and one for the notification listener.
    let pool = match database::connect(&config.database_url, 2).await {
        Ok(pool) => pool,
        Err(e) => {
            error!("failed to connect to database: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The API also migrates; sqlx serialises concurrent runs with an advisory lock, so whichever
    // container starts first creates the schema.
    if let Err(e) = database::migrate(&pool).await {
        error!("failed to run database migrations: {e}");
        return ExitCode::FAILURE;
    }

    let result = match command {
        Command::Run => {
            service::serve(pool, client, config).await;
            Ok(())
        }
        Command::Update { force } => match pool.acquire().await {
            Ok(mut conn) => update::update(&mut conn, &client, &config, Scope::All, force).await,
            Err(e) => Err(e.into()),
        },
        Command::Inspect { .. } => unreachable!("handled above"),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn inspect(client: &reqwest::Client, url: &str, output: &str) -> Result<(), fetch::Error> {
    let page = fetch::page(client, url).await?;

    println!("url:   {}", page.url);
    println!("title: {}", page.title.as_deref().unwrap_or("-"));
    println!("icon candidates:");
    for candidate in &page.icons {
        println!(
            "  {} (size: {}, svg: {})",
            candidate.url,
            candidate
                .size
                .map_or("-".to_owned(), |size| size.to_string()),
            candidate.svg
        );
    }

    let icon = icon::best(client, &page).await?;
    std::fs::write(output, &icon.png)?;
    println!("chose {} -> {output}", icon.source);

    Ok(())
}
