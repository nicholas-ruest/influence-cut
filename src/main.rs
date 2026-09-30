#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use influence_cut::{GraphDocument, RevocationRequest, build_plan, render_human, validate_graph};
use serde::de::DeserializeOwned;
use std::{fs, path::PathBuf, process::ExitCode};

#[derive(Debug, Parser)]
#[command(
    name = "influence-cut",
    version,
    about = "Plan bounded repair of provenance-linked agent state"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a provenance graph without producing a repair plan.
    Validate {
        /// Path to the provenance graph JSON document.
        #[arg(long)]
        graph: PathBuf,
    },
    /// Compute the affected closure and an ordered repair/replay plan.
    Plan {
        /// Path to the provenance graph JSON document.
        #[arg(long)]
        graph: PathBuf,
        /// Path to the revocation request JSON document.
        #[arg(long)]
        request: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Validate { graph } => {
            let graph: GraphDocument = read_json(&graph)?;
            validate_graph(&graph)?;
            println!("VALID nodes={}", graph.nodes.len());
            Ok(ExitCode::SUCCESS)
        }
        Command::Plan {
            graph,
            request,
            format,
        } => {
            let graph: GraphDocument = read_json(&graph)?;
            let request: RevocationRequest = read_json(&request)?;
            let plan = build_plan(&graph, &request)?;
            match format {
                OutputFormat::Human => print!("{}", render_human(&plan)),
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plan)?),
            }
            Ok(if plan.executable {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}

fn read_json<T: DeserializeOwned>(path: &PathBuf) -> Result<T, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}
