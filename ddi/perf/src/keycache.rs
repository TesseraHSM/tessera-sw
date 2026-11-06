// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host RSA keys kept between runs.
//!
//! Generating RSA keys on the host is by far the slowest part of setup at the
//! default `--keys`: minutes for RSA-2K and hours for RSA-4K on one core. So
//! generated keys are kept in a cache directory: a run takes the first
//! `--keys` keys of a size from the cache, and generates (across the host's
//! cores) and adds only the keys it lacks; `keygen` fills the cache ahead of
//! time. Reuse across runs gives the device nothing to exploit: every keyed
//! run starts with a factory reset, and the keys within a run stay distinct.

use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use tsra_crypto::ExportableKey;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::RsaPrivateKey;
use zeroize::Zeroizing;

use crate::setup::par_map;

/// A DER-encoded RSA private key.
pub(crate) type RsaDer = Zeroizing<Vec<u8>>;

/// The default cache directory: `tsra_ddi_perf` under `$XDG_CACHE_HOME`,
/// `~/.cache` or, on Windows, `%LOCALAPPDATA%`.
pub(crate) fn default_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))?;
    Some(base.join("tsra_ddi_perf"))
}

/// The cache file for `bytes`-byte moduli: DER private keys, each preceded
/// by its length as a little-endian `u32`.
fn cache_file(dir: &Path, bytes: usize) -> PathBuf {
    dir.join(format!("rsa-{}.keys", bytes * 8))
}

/// `n` distinct host RSA private keys with `bytes`-byte moduli: those `dir`
/// holds, and as many more as are needed, generated and added to `dir`.
/// Without `dir`, all are generated. `say` reports generation.
pub(crate) fn rsa_keys(
    dir: Option<&Path>,
    bytes: usize,
    n: usize,
    say: impl Fn(String),
) -> Result<Vec<RsaDer>, String> {
    let file = dir.map(|d| cache_file(d, bytes));
    let mut keys = match &file {
        Some(f) => load(f)?,
        None => Vec::new(),
    };
    if keys.len() < n {
        let missing = n - keys.len();
        say(format!(
            "generating {missing} RSA-{} keys on the host{}",
            bytes * 8,
            file.as_ref()
                .map_or(String::new(), |f| format!(", for {}", f.display()))
        ));
        keys.extend(par_map(missing, |_| {
            let key =
                RsaPrivateKey::generate(bytes).map_err(|e| format!("host RSA keygen: {e:?}"))?;
            key.to_vec()
                .map(Zeroizing::new)
                .map_err(|e| format!("RSA DER export: {e:?}"))
        })?);
        if let Some(f) = &file {
            save(f, &keys)?;
        }
    }
    keys.truncate(n);
    Ok(keys)
}

/// The keys in `file`; none if it does not exist. A torn last record, from
/// a write cut short, is dropped.
fn load(file: &Path) -> Result<Vec<RsaDer>, String> {
    let data = match fs::read(file) {
        Ok(d) => Zeroizing::new(d),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("read {}: {e}", file.display())),
    };
    Ok(parse(&data))
}

fn parse(mut data: &[u8]) -> Vec<RsaDer> {
    let mut keys = Vec::new();
    while let Some((len, rest)) = data.split_first_chunk::<4>() {
        let len = u32::from_le_bytes(*len) as usize;
        let Some(der) = rest.get(..len) else {
            break;
        };
        keys.push(Zeroizing::new(der.to_vec()));
        data = &rest[len..];
    }
    keys
}

/// Replace `file` with `keys`, through a temporary file renamed over it so
/// that a concurrent reader never sees a partial file. Private keys, so
/// readable by the owner alone.
fn save(file: &Path, keys: &[RsaDer]) -> Result<(), String> {
    let dir = file.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut data = Zeroizing::new(Vec::new());
    for key in keys {
        data.extend_from_slice(&(key.len() as u32).to_le_bytes());
        data.extend_from_slice(key);
    }
    let tmp = file.with_extension(format!("tmp{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&tmp)
        .and_then(|mut f| f.write_all(&data))
        .and_then(|()| fs::rename(&tmp, file))
        .map_err(|e| format!("write {}: {e}", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_round_trips_and_drops_a_torn_record() {
        let dir =
            std::env::temp_dir().join(format!("tsra_ddi_perf_keycache_{}", std::process::id()));
        let file = cache_file(&dir, 256);
        let keys: Vec<RsaDer> = [&b"first"[..], b"second key"]
            .iter()
            .map(|k| Zeroizing::new(k.to_vec()))
            .collect();
        save(&file, &keys).expect("save");
        assert_eq!(load(&file).expect("load"), keys);

        let mut torn = fs::read(&file).expect("read");
        torn.truncate(torn.len() - 1);
        assert_eq!(parse(&torn), keys[..1]);
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
