
use crate::utils::cryptography::PublicKey;
use std::time::{SystemTime, UNIX_EPOCH};
use rand;
use rand::Rng;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::io::{Read, Write, Error, ErrorKind};
use std::io;
use bincode;




#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub uid: u128,
    pub title: String,
    pub email_uids: Vec<u128>,
    
    pub filter_addresses: Vec<String>,
}

impl Group {
    pub fn new(title: String, filter_addresses: Vec<String>) -> Self {
        Group {
            uid: gen_uid(),
            title,
            email_uids: Vec::new(),
            filter_addresses: filter_addresses.into_iter().map(|a| a.to_lowercase()).collect(),
        }
    }
}


#[allow(non_snake_case)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub uid: u128,
    pub username: String,
    /// Password token (hashed client-side); stored as plain string and compared directly.
    pub passwordHash: Option<String>,
    pub publicKey: Option<PublicKey>,
    pub userCreated: u64,
    pub lastLogin: u64,
    pub emailIds: Vec<u128>,
    #[serde(default)]
    pub sent_emails: Vec<u128>,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub groups: Vec<Group>,
    /// Per-user random salt (hex string) used by the client for key derivation.
    #[serde(default = "gen_salt")]
    pub salt: String,
    /// AES-256 encrypted private key blob (encrypted client-side), stored as base64.
    #[serde(default)]
    pub encrypted_private_key: Option<String>,
    /// One-time provisioning secret for accounts created without a password.
    /// The user presents this as their password on first login, which grants a
    /// 'force_reset' session that may only be used to call '/api/user/setup'.
    /// Cleared as soon as a real password is set.
    #[serde(default)]
    pub setup_token: Option<String>,
    /// Unix seconds of the last credential change made by someone other than the
    /// session holder (admin password reset, admin demotion). Sessions issued
    /// before this instant are rejected - see 'utils::jwt' and the router.
    #[serde(default)]
    pub credentials_changed_at: u64,
}

impl User {
    #[allow(dead_code)]
    pub fn new(uid: u128, username: String, password_hash: String, public_key: PublicKey, salt: String, encrypted_private_key: Option<String>) -> Self {
        let mut user = User {
            uid,
            username,
            passwordHash: Some(password_hash),
            publicKey: Some(public_key),
            userCreated: 0,
            lastLogin: 0,
            emailIds: Vec::new(),
            sent_emails: Vec::new(),
            is_admin: false,
            groups: Vec::new(),
            salt,
            encrypted_private_key,
            setup_token: None,
            credentials_changed_at: 0,
        };
        user.seal_password();
        user
    }

    /// Wrap the stored hash with the per-account pepper. Idempotent, so it is safe
    /// to call after any assignment to 'passwordHash'.
    pub fn seal_password(&mut self) {
        if let Some(hash) = &self.passwordHash {
            if crate::utils::password::is_legacy(hash) {
                self.passwordHash = Some(crate::utils::password::wrap(&self.salt, hash));
            }
        }
    }

    /// Verify against the peppered hash, falling back to legacy hashes so that
    /// accounts created before peppering still log in (and can be upgraded).
    pub fn verify_password_peppered(&self, presented: &str) -> bool {
        match &self.passwordHash {
            Some(hash) => crate::utils::password::verify(hash, &self.salt, presented),
            None => self.verify_password(presented),
        }
    }

    pub fn create_user(username: String, password_hash: String, public_key: PublicKey, encrypted_private_key: String) -> Self {
        let uid = gen_uid();
        let mut user = User {
            uid,
            username,
            passwordHash: Some(password_hash),
            publicKey: Some(public_key),
            userCreated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            lastLogin: 0,
            emailIds: Vec::new(),
            sent_emails: Vec::new(),
            is_admin: false,
            groups: Vec::new(),
            salt: gen_salt(),
            encrypted_private_key: Some(encrypted_private_key),
            setup_token: None,
            credentials_changed_at: 0,
        };
        user.seal_password();
        user
    }

    /// Create an account that has no password yet. The returned user carries a
    /// freshly generated one-time 'setup_token' which the account owner must
    /// present as their password on first login; it is the only credential that
    /// authenticates the account until '/api/user/setup' runs.
    pub fn create_provisioned_user(username: String, is_admin: bool) -> Self {
        let uid = gen_uid();
        User {
            uid,
            username,
            passwordHash: None,
            publicKey: None,
            userCreated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            lastLogin: 0,
            emailIds: Vec::new(),
            sent_emails: Vec::new(),
            is_admin,
            groups: Vec::new(),
            salt: gen_salt(),
            encrypted_private_key: None,
            setup_token: Some(gen_setup_token()),
            credentials_changed_at: 0,
        }
    }

    /// Constant-time credential check.
    ///
    /// An account with no password hash is NOT open to everyone: it can only be
    /// unlocked with its one-time setup token. An account with neither a hash nor
    /// a token cannot be authenticated at all.
    pub fn verify_password(&self, presented: &str) -> bool {
        match (&self.passwordHash, &self.setup_token) {
            (Some(hash), _) => constant_time_eq(hash.as_bytes(), presented.as_bytes()),
            (None, Some(token)) => constant_time_eq(token.as_bytes(), presented.as_bytes()),
            (None, None) => false,
        }
    }

    pub fn needs_force_reset(&self) -> bool {
        self.passwordHash.is_none()
    }

    /// Record that the account's credentials were changed by an administrator,
    /// invalidating every session token issued before this moment.
    pub fn revoke_existing_sessions(&mut self) {
        self.credentials_changed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }
}

/// Compare two byte strings without leaking their contents through timing.
/// Length is not secret here (both sides are fixed-width hex/base64 digests),
/// but the comparison itself always walks the full buffer.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Usernames become the local part of an email address and are used as storage
/// keys, so they are restricted to an unambiguous, canonical character set.
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() || username.len() > 64 {
        return Err("Username must be between 1 and 64 characters");
    }
    if !username.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')) {
        return Err("Username may only contain lowercase letters, digits, '.', '_' and '-'");
    }
    let first = username.as_bytes()[0];
    let last = username.as_bytes()[username.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err("Username must start and end with a letter or digit");
    }
    if username.contains("..") {
        return Err("Username may not contain consecutive dots");
    }
    Ok(())
}

fn gen_uid() -> u128 {
    let mut rng = rand::thread_rng();
    rng.r#gen::<u128>()
}

pub fn gen_salt() -> String {
    let mut rng = rand::thread_rng();
    let a: u64 = rng.r#gen();
    let b: u64 = rng.r#gen();
    format!("{:016x}{:016x}", a, b)
}

/// SHA-256 of a secret, hex encoded. Reset tokens are stored only in this form.
pub fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// 256 bits of OS entropy, hex encoded - this value is a password equivalent.
pub fn gen_setup_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}





/// The account store is positional bincode, so adding a field to `User` makes
/// every existing record unreadable with no way to tell why: the decode simply
/// fails and the store looks empty. A header cannot fix that on its own, but it
/// makes the failure legible and, together with the empty-store guard, stops a
/// bad decode from being written back over the real accounts.
const USER_STORE_MAGIC: &[u8; 8] = b"ONUSERS1";

/// A store smaller than this cannot contain an account, so a decode that yields
/// zero users from a larger file is a failure, not an empty server.
const SMALLEST_POPULATED_STORE: usize = 64;

/// Does the map length prefix fit inside the file at all?
///
/// bincode is not defensive: a corrupt length prefix of 0xABABABAB makes it try
/// to reserve exabytes and abort the process instead of returning an error. A
/// store cannot hold more entries than it has bytes, so that is the test.
fn length_prefix_fits(body: &[u8]) -> bool {
    if body.len() < 8 {
        return false;
    }
    let declared = u64::from_le_bytes(match body[..8].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    });
    declared <= body.len() as u64
}

/// Decode either the current format or the unheadered one written before it.
fn decode_users(raw: &[u8]) -> Result<HashMap<String, User>, bincode::Error> {
    let body = if raw.len() >= USER_STORE_MAGIC.len() && &raw[..USER_STORE_MAGIC.len()] == USER_STORE_MAGIC {
        &raw[USER_STORE_MAGIC.len()..]
    } else {
        // Written before the header existed: read it, and it is rewritten with
        // the header on the next save.
        raw
    };

    if !length_prefix_fits(body) {
        return Err(Box::new(bincode::ErrorKind::Custom(
            "account store length prefix does not fit the file".to_string(),
        )));
    }

    bincode::deserialize_from(body)
}

fn encode_users(users: &HashMap<String, User>) -> Result<Vec<u8>, bincode::Error> {
    let body = bincode::serialize(users)?;
    let mut out = Vec::with_capacity(USER_STORE_MAGIC.len() + body.len());
    out.extend_from_slice(USER_STORE_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

pub struct UserStorage {
    users: Mutex<HashMap<String, User>>,
    filename: String,
    pub domain: String,
    /// Set when the file on disk could not be read. Writing over an unreadable
    /// store would replace every account with the empty map we are holding.
    blocked: std::sync::atomic::AtomicBool,
}

impl UserStorage {
    /// Acquire the user map, tolerating a poisoned lock.
    ///
    /// The guarded data is a plain map that is never left half-updated, so if
    /// some other thread panicked while holding this lock there is nothing to
    /// recover - and propagating the poison would turn one panic into a
    /// permanent, server-wide outage on every subsequent request.
    fn lock_users(&self) -> std::sync::MutexGuard<'_, HashMap<String, User>> {
        match self.users.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!("[Storage] User map lock was poisoned by an earlier panic; continuing");
                poisoned.into_inner()
            }
        }
    }

    pub fn new(filename: String, domain: String) -> Self {
        UserStorage {
            users: Mutex::new(HashMap::new()),
            filename,
            domain,
            blocked: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Refuse every write until an operator fixes whatever could not be read.
    fn block_writes(&self) {
        self.blocked.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn writes_blocked(&self) -> bool {
        self.blocked.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The account that answers the addresses nobody signs in as.
    ///
    /// RFC 5321 requires `postmaster@` to be deliverable and complaints are
    /// expected at `abuse@`; neither is a real user, and both are reserved so a
    /// customer cannot claim them. They route to the first administrator, so the
    /// front door can honestly accept mail the standards say must be accepted.
    ///
    ///  is here for a different reason: it is where the MTA sends its own
    /// failure notices. Refusing it turned every Postfix notification — queue
    /// trouble, a bounce it could not deliver, a watchdog complaint — into a
    /// second bounce, so operator mail went nowhere at all.
    pub fn role_owner(&self, local: &str) -> Option<String> {
        let lower = local.to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "postmaster" | "abuse" | "hostmaster" | "root"
        ) {
            return None;
        }
        // A named owner first: a complaint must reach someone who reads it.
        if let Some(configured) = crate::config::role_owner_username() {
            if let Some(user) = self.get_user(&configured) {
                if user.is_admin {
                    return Some(user.username);
                }
                log::warn!(
                    "[SMTP] roles.owner '{}' is not an administrator; falling back to the first admin",
                    configured
                );
            } else {
                log::warn!(
                    "[SMTP] roles.owner '{}' does not exist; falling back to the first admin",
                    configured
                );
            }
        }
        let mut admins: Vec<String> = self
            .get_all_users()
            .into_iter()
            .filter(|candidate| candidate.is_admin)
            .map(|candidate| candidate.username)
            .collect();
        admins.sort();
        admins.into_iter().next()
    }

    pub fn add_user(&self, user: User) {
        let mut users = self.lock_users();
        users.insert(user.username.clone(), user);
    }

    /// The key an address actually lives under, matched without regard to case.
    ///
    /// Addresses are not case-sensitive: Admin@slothlee.xyz and admin@slothlee.xyz
    /// are one mailbox. Keys are normally stored lowercase, but an account created
    /// before that rule can carry capitals, so an exact miss falls back to a scan.
    /// If two keys differ only by case we refuse to guess: silently merging two
    /// accounts is worse than making the caller pick one.
    fn resolve_key(users: &std::collections::HashMap<String, User>, username: &str) -> Option<String> {
        if users.contains_key(username) {
            return Some(username.to_string());
        }
        let needle = username.to_ascii_lowercase();
        let mut found: Option<String> = None;
        for key in users.keys() {
            if key.to_ascii_lowercase() == needle {
                if found.is_some() {
                    return None;
                }
                found = Some(key.clone());
            }
        }
        found
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        let users = self.lock_users();
        match Self::resolve_key(&users, username) {
            Some(key) => users.get(&key).cloned(),
            None => None,
        }
    }

    pub fn update_user(&self, user: User) {
        let mut users = self.lock_users();
        users.insert(user.username.clone(), user);
    }

    /// Mutate a user in place, under the same lock that guards the map.
    ///
    /// Replacing whole user objects (get -> clone -> update) loses concurrent
    /// writes: a login that cloned before a delivery overwrites the new email
    /// id on save. Callers that change one field must use this instead.
    pub fn mutate_user<F: FnOnce(&mut User)>(&self, username: &str, f: F) -> bool {
        let mut users = self.lock_users();
        let key = match Self::resolve_key(&users, username) {
            Some(k) => k,
            None => return false,
        };
        match users.get_mut(&key) {
            Some(user) => { f(user); true }
            None => false,
        }
    }

    /// Find an account by its numeric uid (used when reconciling blob ownership).
    pub fn get_user_by_uid(&self, uid: u128) -> Option<User> {
        let users = self.lock_users();
        users.values().find(|u| u.uid == uid).cloned()
    }

    pub fn check_user_exists(&self, username: &str) -> bool {
        let users = self.lock_users();
        Self::resolve_key(&users, username).is_some()
    }

    pub fn delete_user(&self, username: &str) -> Vec<u128> {
        let mut users = self.lock_users();
        let key = Self::resolve_key(&users, username);
        let removed = key.and_then(|k| users.remove(&k));
        if let Some(user) = removed {
            user.emailIds.clone()
        } else {
            Vec::new()
        }
    }

    pub fn get_user_count(&self) -> usize {
        let users = self.lock_users();
        users.len()
    }

    #[allow(dead_code)]
    pub fn get_users_bulk(&self, usernames: Vec<String>) -> Vec<User> {
        let users = self.lock_users();
        let mut result = Vec::new();
        for username in usernames {
            if let Some(user) = users.get(&username) {
                result.push(user.clone());
            }
        }
        result
    }

    pub fn get_all_users(&self) -> Vec<User> {
        let users = self.lock_users();
        users.values().cloned().collect()
    }

    

    
    pub fn add_group(&self, username: &str, group: Group) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            user.groups.push(group);
            true
        } else {
            false
        }
    }

    
    pub fn update_group(&self, username: &str, updated: Group) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            if let Some(g) = user.groups.iter_mut().find(|g| g.uid == updated.uid) {
                *g = updated;
                return true;
            }
        }
        false
    }

    
    pub fn delete_group(&self, username: &str, group_uid: u128) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            let before = user.groups.len();
            user.groups.retain(|g| g.uid != group_uid);
            return user.groups.len() < before;
        }
        false
    }

    
    /// Drop every reference to a message whose blob no longer exists.
    ///
    /// The index is the source of truth for what a mailbox contains, but a blob
    /// can vanish (manual cleanup, a failed write, a partial restore). Without
    /// this, the phantom entry survives every restart and errors on each open.
    pub fn detach_email(&self, username: &str, email_uid: u128) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            let indexed = user.emailIds.contains(&email_uid);
            let sent = user.sent_emails.contains(&email_uid);
            user.emailIds.retain(|id| *id != email_uid);
            user.sent_emails.retain(|id| *id != email_uid);
            for group in &mut user.groups {
                group.email_uids.retain(|id| *id != email_uid);
            }
            return indexed || sent;
        }
        false
    }

    pub fn remove_email_from_groups(&self, username: &str, email_uid: u128) {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            for group in &mut user.groups {
                group.email_uids.retain(|&id| id != email_uid);
            }
        }
    }

    
    pub fn add_email_to_matching_groups(&self, username: &str, email_uid: u128, sender_email: &str) {
        let sender_lower = sender_email.to_lowercase();
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            for group in &mut user.groups {
                if group.filter_addresses.iter().any(|addr| addr == &sender_lower) {
                    if !group.email_uids.contains(&email_uid) {
                        group.email_uids.push(email_uid);
                    }
                }
            }
        }
    }

    
    pub fn add_email_to_group(&self, username: &str, group_uid: u128, email_uid: u128) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            if let Some(group) = user.groups.iter_mut().find(|g| g.uid == group_uid) {
                if !group.email_uids.contains(&email_uid) {
                    group.email_uids.push(email_uid);
                }
                return true;
            }
        }
        false
    }

    
    pub fn remove_email_from_group(&self, username: &str, group_uid: u128, email_uid: u128) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            if let Some(group) = user.groups.iter_mut().find(|g| g.uid == group_uid) {
                group.email_uids.retain(|&id| id != email_uid);
                return true;
            }
        }
        false
    }


    
    pub fn save_to_file(&self) -> io::Result<()> {
        let users = self.lock_users();
        
        if self.writes_blocked() {
            return Err(Error::new(
                ErrorKind::Other,
                "account store is read-only: the file could not be read at startup",
            ));
        }

        let data = encode_users(&*users)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        // Never truncate the live file: write a sibling and rename over it, so a
        // crash, a full disk or a backup read mid-write cannot leave the account
        // store empty. Truncate-then-write lost a whole mailbox the once it happened.
        let tmp = format!("{}.tmp", self.filename);
        {
            let mut file = File::create(&tmp)?;
            file.write_all(&data)?;
            file.sync_all()?;
        }

        // Keep the previous good copy for recovery from a bad write.
        if Path::new(&self.filename).exists() {
            let _ = std::fs::copy(&self.filename, format!("{}.bak", self.filename));
        }

        std::fs::rename(&tmp, &self.filename)?;

        // Make the rename itself durable.
        if let Some(dir) = Path::new(&self.filename).parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    pub fn load_from_file(&self) -> io::Result<()> {
        let read = |path: &str| -> io::Result<HashMap<String, User>> {
            let mut file = File::open(path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            let users = decode_users(&data).map_err(|e| Error::new(ErrorKind::Other, e))?;
            // An empty map out of a file that cannot be that small means the
            // decode read something it did not understand.
            if users.is_empty() && data.len() >= SMALLEST_POPULATED_STORE {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "{} bytes of account store decoded to zero accounts",
                        data.len()
                    ),
                ));
            }
            Ok(users)
        };

        let users = match read(&self.filename) {
            Ok(u) => u,
            Err(primary) => {
                // A corrupt live file must not mean "no accounts": try the copy
                // taken before the last write before giving up.
                let backup = format!("{}.bak", self.filename);
                match read(&backup) {
                    Ok(u) => {
                        log::warn!(
                            "[Storage] {} unreadable ({}); recovered {} account(s) from {}",
                            self.filename, primary, u.len(), backup
                        );
                        u
                    }
                    Err(_) => {
                        // Both the live file and the pre-write copy are unreadable.
                        // Nothing may be written: the in-memory map is empty and
                        // saving it would destroy every account on disk.
                        self.block_writes();
                        log::error!(
                            "[Storage] {} and {}.bak are both unreadable; the account store is now read-only",
                            self.filename, self.filename
                        );
                        return Err(primary);
                    }
                }
            }
        };

        let mut users_lock = self.lock_users();
        *users_lock = users;
        Ok(())
    }

}

pub fn get_or_init_storage(filename: String, domain: String) -> UserStorage {
    let storage = UserStorage::new(filename.clone(), domain);
    match storage.load_from_file() {
        Ok(_) => {
            log::info!("[Storage] Loaded {} users from '{}'", storage.get_user_count(), filename);
            storage
        },
        Err(e) => {
            // A file that exists but will not parse is not the same as a missing
            // one. Treating it as missing is how an unreadable store becomes an
            // empty one on the next save.
            let unusable_existing = std::path::Path::new(&filename)
                .metadata()
                .map(|meta| meta.len() > 0)
                .unwrap_or(false);
            if unusable_existing {
                log::error!(
                    "[Storage] '{}' exists but could not be read ({}). Refusing to create a replacement store: \
                     the account store is read-only until this is fixed. The copy from before the last write is '{}.bak'.",
                    filename,
                    e,
                    filename
                );
                storage.block_writes();
                return storage;
            }
            log::warn!("[Storage] No existing user storage at '{}': {}. Creating new store.", filename, e);

            
            if let Some(parent) = std::path::Path::new(&filename).parent() {
                if let Err(dir_err) = std::fs::create_dir_all(parent) {
                    log::error!("[Storage] Failed to create directory: {}", dir_err);
                }
            }

            
            let admin_user = User::create_provisioned_user("admin".to_string(), true);
            let setup_token = admin_user.setup_token.clone().unwrap_or_default();
            storage.add_user(admin_user);

            if let Err(save_err) = storage.save_to_file() {
                log::error!("[Storage] Failed to save initial user storage: {}", save_err);
            }

            // The bootstrap admin has no password. This token is the ONLY credential
            // that unlocks it, and it is shown exactly once per fresh data directory.
            log::warn!(
                "[Storage] Bootstrap admin created. Log in as 'admin' using this one-time \
                 setup token as the password, then set a real password immediately:\n\
                 \n    {}\n",
                setup_token
            );

            storage
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwordless_accounts_are_not_open_to_everyone() {
        let user = User::create_provisioned_user("alice".to_string(), false);
        let token = user.setup_token.clone().unwrap();

        assert!(!user.verify_password("anything"), "any password unlocked a provisioned account");
        assert!(!user.verify_password(""), "empty password unlocked a provisioned account");
        assert!(user.verify_password(&token), "the setup token should unlock the account");
    }

    #[test]
    fn an_account_with_no_credential_at_all_cannot_authenticate() {
        let mut user = User::create_provisioned_user("bob".to_string(), false);
        user.setup_token = None;
        assert!(!user.verify_password(""));
        assert!(!user.verify_password("anything"));
    }

    #[test]
    fn a_configured_password_ignores_any_leftover_setup_token() {
        let mut user = User::create_provisioned_user("carol".to_string(), false);
        let token = user.setup_token.clone().unwrap();
        user.passwordHash = Some("hashed".to_string());

        assert!(user.verify_password("hashed"));
        assert!(!user.verify_password(&token));
    }

    #[test]
    fn provisioned_accounts_are_not_admins_by_default() {
        assert!(!User::create_provisioned_user("dave".to_string(), false).is_admin);
        assert!(User::create_provisioned_user("root".to_string(), true).is_admin);
    }

    #[test]
    fn setup_tokens_are_unique_and_long() {
        let a = gen_setup_token();
        let b = gen_setup_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn usernames_are_restricted_to_a_safe_character_set() {
        for ok in ["alice", "bob.smith", "a", "user-1", "x_y"] {
            assert!(validate_username(ok).is_ok(), "rejected valid username: {}", ok);
        }
        for bad in ["", "../etc", "a@b", "Alice", "with space", ".leading", "trailing.", "a..b", "a/b", &"x".repeat(65)] {
            assert!(validate_username(bad).is_err(), "accepted invalid username: {}", bad);
        }
    }

    #[test]
    fn email_uids_do_not_collide_within_the_same_second() {
        let user = User::create_provisioned_user("erin".to_string(), false);
        let uids: std::collections::HashSet<u128> = (0..1000)
            .map(|_| crate::utils::emailutils::generate_email_uid(&user))
            .collect();
        assert_eq!(uids.len(), 1000, "generated colliding email UIDs");
    }
}

#[cfg(test)]
mod store_format_tests {
    use super::*;

    fn sample() -> HashMap<String, User> {
        let mut map = HashMap::new();
        let user = User::create_provisioned_user("admin".to_string(), true);
        map.insert(user.username.clone(), user);
        map
    }

    #[test]
    fn the_current_format_round_trips_behind_a_header() {
        let users = sample();
        let encoded = encode_users(&users).expect("encode");
        assert_eq!(&encoded[..8], USER_STORE_MAGIC);
        let decoded = decode_users(&encoded).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert!(decoded.contains_key("admin"));
    }

    #[test]
    fn an_unheadered_store_still_reads() {
        let users = sample();
        let legacy = bincode::serialize(&users).expect("legacy encode");
        let decoded = decode_users(&legacy).expect("legacy decode");
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn a_truncated_store_is_an_error_not_an_empty_server() {
        let users = sample();
        let encoded = encode_users(&users).expect("encode");
        let truncated = &encoded[..encoded.len() / 2];
        assert!(decode_users(truncated).is_err());
    }

    #[test]
    fn rubbish_behind_the_header_is_an_error() {
        let mut broken = USER_STORE_MAGIC.to_vec();
        broken.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(decode_users(&broken).is_err());
    }

    #[test]
    fn an_unreadable_store_comes_up_read_only_instead_of_empty() {
        let dir = std::env::temp_dir().join(format!("on-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("users.bin");
        std::fs::write(&path, vec![0xAB; 512]).expect("write garbage");

        let storage = get_or_init_storage(
            path.to_string_lossy().to_string(),
            "example.test".to_string(),
        );

        assert!(
            storage.writes_blocked(),
            "a store that cannot be read must never be writable"
        );
        assert_eq!(storage.get_user_count(), 0, "no phantom accounts");
        assert!(
            storage.save_to_file().is_err(),
            "saving would replace every account with an empty map"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_guard_threshold_is_larger_than_an_empty_store() {
        let empty = encode_users(&HashMap::new()).expect("encode");
        assert!(empty.len() < SMALLEST_POPULATED_STORE);
    }
}
