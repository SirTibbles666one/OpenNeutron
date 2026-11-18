//! Roles: who may moderate, and who may administer.
//!
//! Today the server has `is_admin: bool` on `User`, and `User` is bincode — so a role field
//! cannot be added without making `users.bin` unreadable for every account. This is a
//! sidecar, matching `trash`, `junk`, `subject_rules` and `suspended`: the same trick has
//! carried four features without ever rewriting the user file, and it carries this one too.
//!
//! The rule, and it is deliberately conservative:
//!
//! * `is_admin == true` on the user record always means **Admin**, whatever the sidecar says.
//!   A file that fails to load must never be able to demote the owner.
//! * the sidecar can grant **Staff**, and can grant **Admin** to an account whose record
//!   already says admin (a no-op), but a staff entry can never demote an admin.
//!
//! Staff may moderate: suspend and unsuspend with a reason, approve or deny signups, read
//! the audit log and mail health. Staff may not delete an account, change credentials or
//! recovery addresses, or grant roles — those are Admin.
//!
//! `data/roles.json`:
//! ```json
//! { "users": { "alice": "staff" } }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const STORE_PATH: &str = "data/roles.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Staff,
    Admin,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Staff => "staff",
            Role::Admin => "admin",
        }
    }

    /// May moderate: suspend, approve signups, read the log and the health card.
    pub fn can_moderate(&self) -> bool {
        matches!(self, Role::Staff | Role::Admin)
    }

    /// May administer: delete, re-key, grant roles.
    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    users: BTreeMap<String, String>,
}

static LOCK: Mutex<()> = Mutex::new(());

fn path() -> PathBuf {
    PathBuf::from(STORE_PATH)
}

fn key(username: &str) -> String {
    username.trim().to_lowercase()
}

fn read_at(path: &Path) -> Store {
    fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_at(path: &Path, store: &Store) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(store)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, path)
}

/// Resolve a role. `is_admin` comes from the user record and wins over the sidecar.
pub fn role_at(path: &Path, username: &str, is_admin: bool) -> Role {
    if is_admin {
        return Role::Admin;
    }
    match read_at(path).users.get(&key(username)).map(|s| s.as_str()) {
        Some("staff") => Role::Staff,
        // A sidecar entry can never promote to Admin on its own: promotion goes through the
        // user record, so a hand-edited file cannot quietly create an administrator.
        Some("admin") | Some("user") | _ => Role::User,
    }
}

pub fn role(username: &str, is_admin: bool) -> Role {
    role_at(&path(), username, is_admin)
}

pub fn set_at(path: &Path, username: &str, role: Role, is_admin: bool) -> io::Result<()> {
    // The one refusal that matters: an admin demoting themselves through this file would
    // lock the owner out of their own panel.
    if is_admin && role != Role::Admin {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "an administrator's role cannot be lowered here",
        ));
    }
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut store = read_at(path);
    let name = key(username);
    match role {
        Role::Staff => {
            store.users.insert(name, "staff".to_string());
        }
        Role::User | Role::Admin => {
            store.users.remove(&name);
        }
    }
    write_at(path, &store)
}

pub fn set(username: &str, role: Role, is_admin: bool) -> io::Result<()> {
    set_at(&path(), username, role, is_admin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("roles-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn admin_wins_over_the_sidecar() {
        let path = tmp("adminwins");
        set_at(&path, "tibs", Role::Staff, true).unwrap_err(); // refused: cannot demote an admin
        assert_eq!(role_at(&path, "tibs", true), Role::Admin);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn staff_is_granted_and_can_moderate_but_not_administer() {
        let path = tmp("staff");
        set_at(&path, "qatester", Role::Staff, false).unwrap();
        let role = role_at(&path, "qatester", false);
        assert_eq!(role, Role::Staff);
        assert!(role.can_moderate());
        assert!(!role.is_admin());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_hand_edited_file_cannot_create_an_admin() {
        let path = tmp("handedit");
        fs::write(&path, r#"{"users":{"mallory":"admin"}}"#).unwrap();
        assert_eq!(role_at(&path, "mallory", false), Role::User);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn clearing_returns_to_user() {
        let path = tmp("clear");
        set_at(&path, "qatester", Role::Staff, false).unwrap();
        set_at(&path, "qatester", Role::User, false).unwrap();
        assert_eq!(role_at(&path, "qatester", false), Role::User);
        let _ = fs::remove_file(&path);
    }
}
