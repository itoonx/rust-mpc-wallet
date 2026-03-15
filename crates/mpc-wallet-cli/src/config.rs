use std::path::PathBuf;

/// Get the default data directory for key storage.
pub fn data_dir() -> PathBuf {
    dirs_or_default().join("mpc-wallet")
}

fn dirs_or_default() -> PathBuf {
    if let Some(dir) = dirs::data_dir() {
        dir
    } else {
        PathBuf::from(".mpc-wallet")
    }
}

/// Get the key store directory.
pub fn key_store_dir() -> PathBuf {
    data_dir().join("keys")
}
