use serde::Serialize;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

pub fn print_result<T: Serialize + std::fmt::Display>(value: &T, format: OutputFormat) {
    match format {
        OutputFormat::Text => println!("{value}"),
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(value).unwrap_or_else(|_| format!("{value}"))
            );
        }
    }
}

/// A generic result type for CLI output.
#[derive(Debug, Serialize)]
pub struct CliResult {
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl std::fmt::Display for CliResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.status, self.message)?;
        if let Some(data) = &self.data {
            write!(f, "\n{}", serde_json::to_string_pretty(data).unwrap_or_default())?;
        }
        Ok(())
    }
}
