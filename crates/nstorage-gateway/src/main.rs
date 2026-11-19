use clap::Parser;
use nstorage_gateway::{router, AppState, Config};

#[derive(Parser)]
#[command(about = "nstorage gateway")]
struct Args {
    /// Path to JSON config.
    #[arg(long, env = "NSTORAGE_CONFIG")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args = Args::parse();
    let cfg: Config = serde_json::from_slice(&std::fs::read(&args.config)?)?;
    let listen = cfg.listen.clone();
    let state = AppState::new(cfg).await?;
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!("nstorage gateway listening on {listen}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
