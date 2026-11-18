//! Published ML-DSA-65 signing keys, one per account.
//!
//! A signature is only worth something if the recipient can check it against a key
//! the directory cannot swap under them. The key-transparency log commits to a
//! *hash* of this key (`keylog::record_signing_key`), and this sidecar serves the
//! key itself so a sender can verify a signature and then check the hash against
//! the log's signed head. Neither half is useful alone: a key without a logged hash
//! is just the server's word again, and a hash without the key cannot verify
//! anything.
//!
//! Sidecar, not `struct User` — `users.bin` is bincode with positional fields, and
//! adding one here would make every existing account unreadable. Same reason
//! `pqkeys` and `sessions` live in their own files.
//!
//! The value stored is the **full** public key, base64, exactly as the client
//! published it. The server never needs it to do anything but hand it back; the
//! private half never leaves the browser, and no signature is verified here.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// ML-DSA-65 verifying keys are 1952 bytes (FIPS 204: 32-byte rho + 6*320-byte t1).
/// A couple of bytes of encoder padding are tolerated because the log commits to a
/// hash of the bytes as sent; anything further from that size is not a key.
const MLDSA65_PK_LEN: usize = 1952;
const MLDSA65_PK_SLACK: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigKey {
    /// Full ML-DSA-65 verifying key, base64. Recipients need all of it.
    pub public_key: String,
    /// Unix seconds at which it was published.
    pub created_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SigKeyStore {
    #[serde(default)]
    entries: HashMap<String, SigKey>,
}

fn store_path() -> PathBuf {
    // A test that writes here points it at a scratch directory; the override is
    // thread-local so parallel tests cannot redirect each other.
    #[cfg(test)]
    if let Some(path) = test_path() {
        return path;
    }
    PathBuf::from("data/sigkeys.json")
}

#[cfg(test)]
thread_local! {
    static TEST_PATH: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_path() -> Option<PathBuf> {
    TEST_PATH.with(|p| p.borrow().clone())
}

/// Read the sidecar from disk on every call.
///
/// The file is tiny and read far less often than mail; a cache that disagreed with
/// disk would be a key the transparency log does not vouch for, which is exactly
/// the failure this feature exists to prevent.
fn read_store() -> SigKeyStore {
    std::fs::read_to_string(store_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<SigKeyStore>(&raw).ok())
        .unwrap_or_default()
}

fn write_store(store: &SigKeyStore) -> Result<(), String> {
    let path = store_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let body = serde_json::to_vec_pretty(store).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    // Write-then-rename: a half-written file would publish a key nobody can use,
    // and the previous key must stay servable until the new one is complete.
    std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

/// The signing key an account has published, if any.
pub fn get(account: &str) -> Option<SigKey> {
    read_store().entries.get(account).cloned()
}

/// Check that a value could be an ML-DSA-65 verifying key before anything is
/// written. Kept separate from `set` so a caller can append the log entry first:
/// the sidecar must never serve a key the log has not witnessed.
pub fn validate(public_key_b64: &str) -> Result<(), String> {
    let raw = STANDARD
        .decode(public_key_b64.trim())
        .map_err(|_| "sig_key is not base64".to_string())?;
    if raw.len() < MLDSA65_PK_LEN || raw.len() > MLDSA65_PK_LEN + MLDSA65_PK_SLACK {
        return Err(format!(
            "sig_key must be an ML-DSA-65 public key ({} bytes), got {}",
            MLDSA65_PK_LEN,
            raw.len()
        ));
    }
    Ok(())
}

/// Publish (or replace) an account's signing key.
///
/// Validates the encoding and the size before storing: a truncated or non-key
/// value would be handed to senders that cannot verify against it, and the log
/// would then commit to the hash of an unusable key.
pub fn set(account: &str, public_key_b64: &str) -> Result<(), String> {
    validate(public_key_b64)?;
    let public_key = public_key_b64.trim();
    let mut store = read_store();
    let created_at = match store.entries.get(account) {
        // Re-publishing the same key is not a new publication; the log will not
        // append either, so the timestamp should not move.
        Some(existing) if existing.public_key == public_key => existing.created_at,
        _ => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    store.entries.insert(
        account.to_string(),
        SigKey {
            public_key: public_key.to_string(),
            created_at,
        },
    );
    write_store(&store)
}

/// Forget an account's signing key.
///
/// Called when the encryption key is removed (a password reset): the log records
/// a removal, and serving the old signing key afterwards would advertise a key
/// with no leaf that witnesses it.
pub fn remove(account: &str) -> Result<(), String> {
    let mut store = read_store();
    if store.entries.remove(account).is_none() {
        return Ok(());
    }
    write_store(&store)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_scratch<F: FnOnce()>(f: F) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sigkeys-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        TEST_PATH.with(|p| *p.borrow_mut() = Some(dir.join("sigkeys.json")));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        TEST_PATH.with(|p| *p.borrow_mut() = None);
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn a_published_key_round_trips() {
        with_scratch(|| {
            let key = STANDARD.encode([7u8; MLDSA65_PK_LEN]);
            set("bob", &key).expect("publish");
            let stored = get("bob").expect("a stored key");
            assert_eq!(stored.public_key, key);
            assert!(stored.created_at > 0);
            assert!(get("alice").is_none());
        });
    }

    #[test]
    fn a_key_that_is_not_an_ml_dsa_65_public_key_is_refused() {
        with_scratch(|| {
            assert!(set("bob", "AAAA").is_err(), "short key");
            assert!(
                set("bob", &STANDARD.encode([1u8; MLDSA65_PK_LEN - 1])).is_err(),
                "one byte short"
            );
            assert!(
                set("bob", &STANDARD.encode([1u8; MLDSA65_PK_LEN + 64])).is_err(),
                "far too long"
            );
            assert!(set("bob", "not base64!").is_err());
            assert!(get("bob").is_none(), "a refused key must not be stored");
        });
    }

    #[test]
    fn republishing_the_same_key_keeps_its_timestamp() {
        with_scratch(|| {
            let key = STANDARD.encode([2u8; MLDSA65_PK_LEN]);
            set("bob", &key).expect("publish");
            let first = get("bob").expect("stored").created_at;
            set("bob", &key).expect("republish");
            assert_eq!(get("bob").expect("stored").created_at, first);
        });
    }

    #[test]
    fn removing_a_key_takes_it_out_of_the_directory() {
        with_scratch(|| {
            let key = STANDARD.encode([4u8; MLDSA65_PK_LEN]);
            set("bob", &key).expect("publish");
            remove("bob").expect("remove");
            assert!(get("bob").is_none());
            // Removing something that was never there is not an error: the
            // password-reset path calls this unconditionally.
            remove("bob").expect("second remove");
        });
    }
}
