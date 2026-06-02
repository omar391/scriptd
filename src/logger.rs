use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub fn append_line(path: &Path, level: &str, message: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(
            file,
            "[{}] [{}] {}",
            Utc::now().to_rfc3339(),
            level,
            message
        );
    }
}

pub fn append_error(path: &Path, message: &str) {
    append_line(path, "ERROR", message);
}

pub fn append_info(path: &Path, message: &str) {
    append_line(path, "INFO", message);
}

pub fn append_warn(path: &Path, message: &str) {
    append_line(path, "WARN", message);
}
