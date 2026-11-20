use clap::{Parser, Subcommand};
use near_drive_gateway::{gc, router, AppState, Config, CONFIG_JSON_ENV};

#[derive(Parser)]
#[command(version, about = "NEAR Drive gateway")]
struct Args {
    /// Path to JSON config. Alternatively set NEAR_DRIVE_CONFIG_JSON to the config itself.
    #[arg(long, env = "NEAR_DRIVE_CONFIG", global = true)]
    config: Option<std::path::PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the gateway API (the default).
    Serve,
    /// Delete chunks no live object references (mark and sweep), once.
    Gc {
        /// Report what would be deleted; delete nothing.
        #[arg(long)]
        dry_run: bool,
        /// Keep unreferenced chunks written within this long (protects uploads
        /// whose record is not committed yet): seconds, or 90s / 15m / 24h / 7d.
        #[arg(long, default_value = "24h", value_parser = gc::parse_duration)]
        grace: std::time::Duration,
        /// Sweep even if the index has no live entries at all.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args = Args::parse();
    let inline = std::env::var(CONFIG_JSON_ENV).ok().filter(|s| !s.trim().is_empty());
    let cfg = Config::load(args.config.as_deref(), inline.as_deref())?;
    match args.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Serve => {
            let listen = cfg.listen.clone();
            let state = AppState::new(cfg).await?;
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            tracing::info!("NEAR Drive gateway listening on {listen}");
            axum::serve(listener, router(state)).await?;
        }
        Cmd::Gc { dry_run, grace, force } => {
            let opts = gc::GcOptions { grace, dry_run, force, ..Default::default() };
            let report = gc::run_config(&cfg, &opts).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            let errors: Vec<_> = report.errors().collect();
            if !errors.is_empty() {
                for (backend, e) in &errors {
                    eprintln!("error: backend {backend}: {e}");
                }
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
