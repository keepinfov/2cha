//! Format-preserving, atomic edits to a config file.
//!
//! These helpers read a TOML file into a `toml_edit::DocumentMut` (which keeps
//! comments and layout), mutate a single dotted key, and write the result back
//! atomically (tmp file + rename). `set_value` runs a caller-supplied validator
//! on the rendered document *before* committing, so a syntactically or
//! semantically invalid edit never lands on disk.

use std::fs;
use std::path::Path;

use toml_edit::{Array, DocumentMut, Item, Table, Value};

use super::common::ConfigError;

/// Read a config file into a `DocumentMut`.
fn read_doc(path: &Path) -> Result<DocumentMut, ConfigError> {
    let content = fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;
    content
        .parse::<DocumentMut>()
        .map_err(|e| ConfigError::ParseError(format!("{}", e)))
}

/// Write a rendered document atomically: tmp file in the same directory, then
/// rename over the target (rename is atomic on the same filesystem).
fn write_atomic(path: &Path, rendered: &str) -> Result<(), ConfigError> {
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, rendered).map_err(|e| ConfigError::IoError(e.to_string()))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        ConfigError::IoError(e.to_string())
    })
}

/// Read → mutate the document → write atomically. Used by the peer helpers.
pub(super) fn edit_config(
    path: &Path,
    mutate: impl FnOnce(&mut DocumentMut) -> Result<(), ConfigError>,
) -> Result<(), ConfigError> {
    let mut doc = read_doc(path)?;
    mutate(&mut doc)?;
    write_atomic(path, &doc.to_string())
}

/// Split a dotted key like `crypto.cipher` into its segments, rejecting empties.
fn key_parts(dotted_key: &str) -> Result<Vec<&str>, ConfigError> {
    let parts: Vec<&str> = dotted_key.split('.').collect();
    if parts.is_empty() || parts.iter().any(|p| p.trim().is_empty()) {
        return Err(ConfigError::Invalid(format!(
            "invalid key path '{}' (expected dotted form like crypto.cipher)",
            dotted_key
        )));
    }
    Ok(parts)
}

/// Get the value at a dotted key, rendered as a plain string (strings come back
/// without their surrounding quotes; other scalars/arrays as their TOML form).
pub fn get_value(path: &Path, dotted_key: &str) -> Result<String, ConfigError> {
    let parts = key_parts(dotted_key)?;
    let doc = read_doc(path)?;

    let mut item: &Item = doc.as_item();
    for (i, key) in parts.iter().enumerate() {
        let table = item.as_table_like().ok_or_else(|| {
            ConfigError::Invalid(format!("'{}' is not a table", parts[..i].join(".")))
        })?;
        item = table.get(key).ok_or_else(|| {
            ConfigError::Invalid(format!("key '{}' not found", parts[..=i].join(".")))
        })?;
    }

    match item.as_value() {
        Some(Value::String(s)) => Ok(s.value().to_string()),
        Some(v) => Ok(v.to_string().trim().to_string()),
        None => Err(ConfigError::Invalid(format!(
            "'{}' is a table or array of tables, not a single value",
            dotted_key
        ))),
    }
}

/// Set the value at a dotted key (creating intermediate tables as needed),
/// inferring the value's type from `raw_value`. The rendered document is passed
/// to `validate`; only if that returns `Ok` is the file written atomically.
pub fn set_value(
    path: &Path,
    dotted_key: &str,
    raw_value: &str,
    validate: impl FnOnce(&str) -> Result<(), ConfigError>,
) -> Result<(), ConfigError> {
    let parts = key_parts(dotted_key)?;
    let mut doc = read_doc(path)?;

    let (leaf, parents) = parts.split_last().expect("key_parts rejects empty");
    let mut table: &mut Table = doc.as_table_mut();
    for key in parents {
        let entry = table.entry(key).or_insert(Item::Table(Table::new()));
        table = entry
            .as_table_mut()
            .ok_or_else(|| ConfigError::Invalid(format!("'{}' is not a table", key)))?;
    }
    // Preserve any surrounding decor (whitespace + inline comment) of the
    // value we're replacing, so `set` doesn't strip a trailing `# comment`.
    let existing_decor = table
        .get(leaf)
        .and_then(|it| it.as_value())
        .map(|v| v.decor().clone());
    let mut new_value = infer_value(raw_value);
    if let Some(decor) = existing_decor {
        *new_value.decor_mut() = decor;
    }
    table[leaf] = Item::Value(new_value);

    let rendered = doc.to_string();
    validate(&rendered)?;
    write_atomic(path, &rendered)
}

/// Infer a TOML value from a raw string: bool → int → float → array → string.
fn infer_value(raw: &str) -> Value {
    let t = raw.trim();
    if t.starts_with('[') && t.ends_with(']') {
        let inner = &t[1..t.len() - 1];
        let mut arr = Array::new();
        for elem in inner.split(',') {
            let e = elem.trim();
            if e.is_empty() {
                continue;
            }
            arr.push(infer_scalar(e));
        }
        return Value::Array(arr);
    }
    infer_scalar(t)
}

/// Infer a scalar TOML value (no arrays). Bare `true`/`false`, integers and
/// floats are typed; anything else becomes a string (surrounding quotes, if the
/// caller supplied them, are stripped).
fn infer_scalar(raw: &str) -> Value {
    let t = raw.trim();
    match t {
        "true" => return Value::from(true),
        "false" => return Value::from(false),
        _ => {}
    }
    if let Ok(i) = t.parse::<i64>() {
        return Value::from(i);
    }
    if let Ok(f) = t.parse::<f64>() {
        return Value::from(f);
    }
    let unquoted = t
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(t);
    Value::from(unquoted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_config(contents: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("twocha-edit-test-{}.toml", std::process::id()));
        // Make each test's file unique enough across calls within the process.
        let unique = format!(
            "{}-{:?}.toml",
            path.display(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::path::PathBuf::from(unique);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    const SAMPLE: &str = "\
# a leading comment
[crypto]
cipher = \"chacha20-poly1305\"  # inline comment

[ipv4]
enable = true
prefix = 24
";

    #[test]
    fn get_returns_unquoted_string() {
        let path = temp_config(SAMPLE);
        assert_eq!(
            get_value(&path, "crypto.cipher").unwrap(),
            "chacha20-poly1305"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn get_returns_scalar() {
        let path = temp_config(SAMPLE);
        assert_eq!(get_value(&path, "ipv4.prefix").unwrap(), "24");
        assert_eq!(get_value(&path, "ipv4.enable").unwrap(), "true");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn get_missing_key_errors() {
        let path = temp_config(SAMPLE);
        assert!(get_value(&path, "crypto.nope").is_err());
        assert!(get_value(&path, "crypto").is_err()); // points at a table
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn set_preserves_comments_and_infers_types() {
        let path = temp_config(SAMPLE);
        set_value(&path, "crypto.cipher", "aes-256-gcm", |_| Ok(())).unwrap();
        set_value(&path, "ipv4.prefix", "16", |_| Ok(())).unwrap();
        let rendered = fs::read_to_string(&path).unwrap();
        assert!(rendered.contains("# a leading comment"));
        assert!(rendered.contains("# inline comment"));
        assert!(rendered.contains("cipher = \"aes-256-gcm\""));
        assert!(rendered.contains("prefix = 16"));
        // The new int must not be quoted.
        assert!(!rendered.contains("prefix = \"16\""));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn set_creates_intermediate_table() {
        let path = temp_config(SAMPLE);
        set_value(&path, "dns.servers_v4", "[1.1.1.1, 8.8.8.8]", |_| Ok(())).unwrap();
        let rendered = fs::read_to_string(&path).unwrap();
        assert!(rendered.contains("[dns]"));
        assert!(rendered.contains("servers_v4"));
        assert!(rendered.contains("\"1.1.1.1\""));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn set_rejected_by_validator_leaves_file_untouched() {
        let path = temp_config(SAMPLE);
        let before = fs::read_to_string(&path).unwrap();
        let err = set_value(&path, "crypto.cipher", "bogus", |_| {
            Err(ConfigError::Invalid("nope".into()))
        });
        assert!(err.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
        // No tmp file left behind.
        assert!(!path.with_extension("toml.tmp").exists());
        let _ = fs::remove_file(&path);
    }
}
