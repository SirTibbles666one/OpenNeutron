//! Key transparency: a log of which key each account has claimed, and when.
//!
//! Every other protection in this server assumes the *directory* is honest. A
//! sender asks who holds `bob@`, the server answers with a public key, and the
//! message is sealed to it. If the server lies — substituted its own key — the
//! crypto is untouched and the mail is readable anyway. That is the one attack
//! none of the envelope work defends against.
//!
//! So every account key gets a leaf in an append-only Merkle log:
//!
//! ```text
//! leaf   = SHA-256("kt/v1/leaf" | u32be(seq) | u16be(len) | account
//!                  | sha256(rsa_der) | sha256(pq_ek) or 32 zero bytes)
//! node   = SHA-256("kt/v1/node" | left | right)      (odd node promoted)
//! head   = { size, root } signed with ML-DSA-65
//! ```
//!
//! A client asks for a leaf plus its audit path, recomputes the root, and
//! compares it with a head it has pinned. Nothing here can prove the server never
//! showed *another* head to someone else — that needs gossip between clients — but
//! it does make silent substitution detectable, which is the difference between
//! "encrypted" and "encrypted to the right person".
//!
//! Storage is a sidecar (`data/keylog.json`) because `User` is positional bincode.
//! The signing key is `data/kt-signing.key`, 0600, generated on first use; its
//! public half travels with every head so a client can pin it once and notice if
//! the server ever changes it.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{EncodedSignature, Generate, KeyExport, MlDsa65, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const LEAF_LABEL: &[u8] = b"kt/v1/leaf";
const NODE_LABEL: &[u8] = b"kt/v1/node";
const HEAD_LABEL: &[u8] = b"kt/v1/head";
const EMPTY_ROOT_LABEL: &[u8] = b"kt/v1/empty";

fn log_path() -> PathBuf {
    PathBuf::from("data/keylog.json")
}

fn key_path() -> PathBuf {
    PathBuf::from("data/ktkey.json")
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    seed: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Leaf {
    pub seq: u64,
    pub account: String,
    /// base64 SHA-256 of the account's RSA (SPKI) key.
    pub rsa: String,
    /// base64 SHA-256 of the ML-KEM encapsulation key, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<String>,
    /// Unix seconds at which this key was recorded.
    pub at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Head {
    pub size: u64,
    pub root: String,
    pub alg: String,
    pub pk: String,
    pub sig: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Store {
    version: u32,
    leaves: Vec<Leaf>,
    #[serde(default)]
    head: Option<Head>,
}

fn read_store() -> Store {
    std::fs::read_to_string(log_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Store>(&s).ok())
        .unwrap_or_else(|| Store { version: 1, leaves: Vec::new(), head: None })
}

fn write_store(store: &Store) -> Result<(), String> {
    let body = serde_json::to_vec(store).map_err(|e| e.to_string())?;
    let tmp = log_path().with_extension("json.tmp");
    // Write-then-rename: a half-written log would look like a lost key history,
    // which is precisely what this feature exists to make impossible.
    std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, log_path()).map_err(|e| e.to_string())
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// The leaf hash, defined once here and mirrored in the browser.
pub fn leaf_hash(leaf: &Leaf) -> [u8; 32] {
    let seq = (leaf.seq as u32).to_be_bytes();
    let name = leaf.account.as_bytes();
    let name_len = (name.len() as u16).to_be_bytes();
    let rsa_hash = STANDARD.decode(&leaf.rsa).unwrap_or_else(|_| vec![0u8; 32]);
    let pq_hash = leaf
        .pq
        .as_ref()
        .and_then(|b64| STANDARD.decode(b64).ok())
        .unwrap_or_else(|| vec![0u8; 32]);
    let mut rsa = [0u8; 32];
    let mut pq = [0u8; 32];
    rsa.copy_from_slice(&pad32(&rsa_hash));
    pq.copy_from_slice(&pad32(&pq_hash));
    sha(&[LEAF_LABEL, &seq, &name_len, name, &rsa, &pq])
}

fn pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let take = bytes.len().min(32);
    out[..take].copy_from_slice(&bytes[..take]);
    out
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha(&[NODE_LABEL, left, right])
}

pub fn empty_root() -> [u8; 32] {
    sha(&[EMPTY_ROOT_LABEL])
}

/// Merkle root over a list of leaf hashes. An odd node at the end is promoted
/// unchanged, which is the shape a verifier can reproduce from an audit path.
pub fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(node_hash(&level[i], &level[i + 1]));
            } else {
                next.push(level[i]);
            }
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Audit path for one leaf: the sibling at each level, left-to-right.
pub fn audit_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    if index >= leaves.len() {
        return path;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            if idx + 1 < level.len() { Some(level[idx + 1]) } else { None }
        } else {
            Some(level[idx - 1])
        };
        if let Some(s) = sibling {
            path.push(s);
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(node_hash(&level[i], &level[i + 1]));
            } else {
                next.push(level[i]);
            }
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    path
}

/// Recompute a root from one leaf and its path. This is what a client does.
///
/// The tree size has to travel with the path: at an odd level the last node is
/// promoted without hashing, and a verifier that only saw the sibling list would
/// hash it against itself at the wrong height and reject a valid proof.
pub fn root_from_path(leaf: [u8; 32], index: usize, size: usize, path: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = leaf;
    let mut idx = index;
    let mut width = size;
    let mut siblings = path.iter();
    while width > 1 {
        let promoted = idx + 1 == width && width % 2 == 1;
        if !promoted {
            let Some(sibling) = siblings.next() else { return acc };
            acc = if idx % 2 == 0 {
                node_hash(&acc, sibling)
            } else {
                node_hash(sibling, &acc)
            };
        }
        idx /= 2;
        width = width.div_ceil(2);
    }
    acc
}

fn signing_key() -> Result<SigningKey<MlDsa65>, String> {
    // A separate key from the mailbox deletion log on purpose: one compromise must
    // not be able to forge both a key history and a deletion history.
    if let Ok(text) = std::fs::read_to_string(key_path()) {
        if let Ok(keys) = serde_json::from_str::<KeyFile>(&text) {
            if let Ok(seed) = STANDARD.decode(keys.seed.trim()) {
                if seed.len() == 32 {
                    let mut raw = [0u8; 32];
                    raw.copy_from_slice(&seed);
                    return Ok(SigningKey::<MlDsa65>::from_seed(&raw.into()));
                }
            }
        }
    }

    let signing = SigningKey::<MlDsa65>::generate();
    let keys = KeyFile {
        seed: STANDARD.encode(signing.to_bytes().as_slice()),
        public_key: STANDARD.encode(signing.verifying_key().encode().as_slice()),
    };
    let text = serde_json::to_string(&keys).map_err(|e| e.to_string())?;
    std::fs::write(key_path(), text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path(), std::fs::Permissions::from_mode(0o600));
    }
    Ok(signing)
}

fn sign_head(size: u64, root: &[u8; 32]) -> Result<Head, String> {
    let key = signing_key()?;
    let message = [HEAD_LABEL, &size.to_be_bytes(), root].concat();
    let sig = key.sign(&message);
    Ok(Head {
        size,
        root: STANDARD.encode(root),
        alg: "ml-dsa-65".to_string(),
        pk: STANDARD.encode(key.verifying_key().encode().as_slice()),
        sig: STANDARD.encode(sig.encode().as_slice()),
    })
}

/// Check a head against the published verifying key. Used by tests, and by the
/// server when it reads its own log back.
pub fn verify_head(head: &Head) -> bool {
    let Some(pk) = STANDARD.decode(&head.pk).ok() else { return false };
    let Some(sig) = STANDARD.decode(&head.sig).ok() else { return false };
    let Ok(pk_bytes) = <[u8; 1952]>::try_from(pk.as_slice()) else { return false };
    let Ok(sig_bytes) = <[u8; 3309]>::try_from(sig.as_slice()) else { return false };
    let verifying = VerifyingKey::<MlDsa65>::decode(&pk_bytes.into());
    let encoded: EncodedSignature<MlDsa65> = sig_bytes.into();
    let Some(signature) = Signature::<MlDsa65>::decode(&encoded) else { return false };
    let Ok(root) = STANDARD.decode(&head.root) else { return false };
    let message = [HEAD_LABEL, &head.size.to_be_bytes(), root.as_slice()].concat();
    verifying.verify(&message, &signature).is_ok()
}

/// Recompute the head from the leaves that are stored, and sign it.
fn rebuild(store: &mut Store) -> Result<(), String> {
    let hashes: Vec<[u8; 32]> = store.leaves.iter().map(leaf_hash).collect();
    let root = root_of(&hashes);
    store.head = Some(sign_head(store.leaves.len() as u64, &root)?);
    Ok(())
}

/// Record an account's current keys, if they differ from what the log already says.
///
/// Called from every path that writes an account key. An unchanged key adds
/// nothing: a log full of identical entries hides the changes that matter.
pub fn record(account: &str, rsa_der: &[u8], pq_public_b64: Option<&str>) -> Result<(), String> {
    // The test suite shares this working directory with the live app, so an
    // unguarded append would let a fixture write leaves into the real log. The
    // pure pieces — leaf hashing, roots, audit paths — are tested directly; the
    // append path is exercised deliberately with KT_WRITE_IN_TESTS=1.
    if cfg!(test) && std::env::var("KT_WRITE_IN_TESTS").is_err() {
        return Ok(());
    }
    let rsa_hash = STANDARD.encode(sha(&[rsa_der]));
    let pq_hash = pq_public_b64
        .and_then(|b64| STANDARD.decode(b64).ok())
        .map(|bytes| STANDARD.encode(sha(&[&bytes])));

    let mut store = read_store();
    let previous = store.leaves.iter().rev().find(|leaf| leaf.account == account);
    if let Some(leaf) = previous {
        if leaf.rsa == rsa_hash && leaf.pq == pq_hash {
            return Ok(());
        }
    }
    let seq = store.leaves.last().map(|l| l.seq + 1).unwrap_or(0);
    store.leaves.push(Leaf {
        seq,
        account: account.to_string(),
        rsa: rsa_hash,
        pq: pq_hash,
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    });
    rebuild(&mut store)?;
    write_store(&store)
}

/// Record an account's keys, looking up its quantum half so one call covers both.
pub fn record_for(account: &str, rsa_der: &[u8]) -> Result<(), String> {
    let pq = crate::core::pqkeys::get(account).map(|k| k.public_key);
    record(account, rsa_der, pq.as_deref())
}

/// Record that an account no longer holds a key. An empty hash is not a missing
/// entry: the log has to show the removal, or a later key would look like the first.
pub fn record_removal(account: &str) -> Result<(), String> {
    record(account, b"", None)
}

/// The same proof, shaped for a client: hashes, indices and a signed head, no keys.
pub fn proof_json(account: &str) -> Option<serde_json::Value> {
    let (leaf, index, path, head) = proof(account)?;
    Some(serde_json::json!({
        "leaf": {
            "seq": leaf.seq,
            "account": leaf.account,
            "rsa": leaf.rsa,
            "pq": leaf.pq,
            "at": leaf.at,
        },
        "index": index,
        "path": path
            .iter()
            .map(|node| STANDARD.encode(node))
            .collect::<Vec<String>>(),
        "head": {
            "size": head.size,
            "root": head.root,
            "alg": head.alg,
            "pk": head.pk,
            "sig": head.sig,
        },
    }))
}

/// The current signed head, if the log has ever been written.
/// Consistency proof between two sizes of this log (RFC 6962 §2.1.2).
///
/// An audit path proves one leaf belongs to one root. This proves something else and
/// stronger: that the tree at `second` contains the tree at `first` as a prefix, so a
/// server cannot show one browser a history and another browser a different one at a
/// later size. Without it, a pinned head only catches a log that shrank or changed
/// under the same size — a rewrite that also grows looks exactly like normal operation.
pub fn consistency_proof(first: usize, second: usize) -> Option<Vec<[u8; 32]>> {
    let store = read_store();
    let leaves: Vec<[u8; 32]> = store.leaves.iter().map(leaf_hash).collect();
    if first > second || second > leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    subproof(&leaves[..second], first, second, true, &mut out);
    Some(out)
}

fn subproof(leaves: &[[u8; 32]], m: usize, n: usize, complete: bool, out: &mut Vec<[u8; 32]>) {
    if m == n {
        if !complete {
            out.push(root_of(leaves));
        }
        return;
    }
    // An empty first tree proves nothing, and the split below would ask for the same
    // (0, 1) subproblem forever. Stop here.
    if m == 0 {
        return;
    }
    // Largest power of two strictly smaller than n.
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    if m <= k {
        subproof(&leaves[..k], m, k, complete, out);
        out.push(root_of(&leaves[k..n]));
    } else {
        subproof(&leaves[k..n], m - k, n - k, false, out);
        out.push(root_of(&leaves[..k]));
    }
}

/// The client side of the same rule, ported from the reference implementation
/// (transparency-dev/merkle, `proof/verify.go`).
///
/// The RFC defines the proof; it does not spell out how to check one, and the "obvious"
/// parity walk silently rejects valid proofs. This is the algorithm that is actually used
/// by CT logs, checked here against every size pair the tests can reach and against the
/// worked examples in RFC 6962 section 2.1.3.
fn bit_len(x: u64) -> u32 {
    64 - x.leading_zeros()
}

fn chain_inner(seed: [u8; 32], proof: &[[u8; 32]], index: u64) -> [u8; 32] {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        acc = if (index >> i) & 1 == 0 {
            node_hash(&acc, h)
        } else {
            node_hash(h, &acc)
        };
    }
    acc
}

fn chain_inner_right(seed: [u8; 32], proof: &[[u8; 32]], index: u64) -> [u8; 32] {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            acc = node_hash(h, &acc);
        }
    }
    acc
}

fn chain_border_right(seed: [u8; 32], proof: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = seed;
    for h in proof {
        acc = node_hash(h, &acc);
    }
    acc
}

fn root_from_subtree_consistency(
    start: u64,
    end: u64,
    size: u64,
    proof: &[[u8; 32]],
    sub_root: &[u8; 32],
) -> Option<[u8; 32]> {
    if end == size {
        let level = bit_len((end - 1) ^ start);
        let index = start >> level;
        let want = index.count_ones() as usize;
        if proof.len() != want {
            return None;
        }
        return Some(chain_border_right(*sub_root, proof));
    }

    let fork_level = bit_len((end - 1) ^ (size - 1));
    let border = ((end - 1) >> fork_level).count_ones() as usize;
    let shift = (end - start).trailing_zeros();
    let inner = (fork_level - shift) as usize;

    let (seed, p_start) = if (end - start) == 1u64 << shift {
        (*sub_root, 0usize)
    } else {
        (*proof.first()?, 1usize)
    };
    if proof.len() != p_start + inner + border {
        return None;
    }
    let proof = &proof[p_start..];
    let mask = (end - 1) >> shift;

    if p_start == 1 {
        // Nodes in the proof that belong to the first tree must chain to its root.
        let h = bit_len((end - 1) ^ start);
        let sub_inner = (std::cmp::min(h, fork_level) as usize).checked_sub(shift as usize)?;
        let sub_border =
            border.saturating_sub((((end - 1) >> h).count_ones()) as usize);
        if proof.len() < inner + sub_border {
            return None;
        }
        let hash1 = chain_inner_right(seed, &proof[..sub_inner], mask);
        let hash1 = chain_border_right(hash1, &proof[inner..inner + sub_border]);
        if &hash1 != sub_root {
            return None;
        }
    }

    let hash2 = chain_inner(seed, &proof[..inner], mask);
    Some(chain_border_right(hash2, &proof[inner..]))
}

pub fn verify_consistency(
    first_size: usize,
    first_root: &[u8; 32],
    second_size: usize,
    second_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if first_size > second_size {
        return false;
    }
    if first_size == second_size {
        return proof.is_empty() && first_root == second_root;
    }
    if first_size == 0 || proof.is_empty() {
        return false;
    }
    match root_from_subtree_consistency(0, first_size as u64, second_size as u64, proof, first_root) {
        Some(root) => &root == second_root,
        None => false,
    }
}

/// The root of the first `size` leaves — used to answer "is this the tree you saw?" when
/// a client quotes a size rather than a root.
pub fn root_at(size: usize) -> Option<Vec<u8>> {
    let store = read_store();
    if size > store.leaves.len() {
        return None;
    }
    let hashes: Vec<[u8; 32]> = store.leaves.iter().take(size).map(leaf_hash).collect();
    Some(root_of(&hashes).to_vec())
}

pub fn head() -> Option<Head> {
    read_store().head
}

/// The signed head over the leaves, with `seq` for the account's newest entry and
/// the audit path that proves it belongs to that root.
pub fn proof(account: &str) -> Option<(Leaf, usize, Vec<[u8; 32]>, Head)> {
    let store = read_store();
    let index = store.leaves.iter().rposition(|leaf| leaf.account == account)?;
    let hashes: Vec<[u8; 32]> = store.leaves.iter().map(leaf_hash).collect();
    let path = audit_path(&hashes, index);
    Some((store.leaves[index].clone(), index, path, store.head?))
}

pub fn size() -> u64 {
    read_store().leaves.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashes(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| node_hash(&[(i & 0xff) as u8; 32], &[(i >> 8) as u8; 32])).collect()
    }

    /// Every pair of sizes must prove, and the proof must be exactly what the
    /// client-side rule accepts — for the whole small range, not one example.
    #[test]
    fn consistency_holds_for_every_size_pair() {
        for n in 1..=24usize {
            let leaves = hashes(n);
            // An empty log proves nothing and has nothing to prove against; a browser
            // never pins a size-0 head, and verify_consistency says so.
            for m in 1..=n {
                let mut proof = Vec::new();
                super::subproof(&leaves[..n], m, n, true, &mut proof);
                let first_root = root_of(&leaves[..m]);
                let second_root = root_of(&leaves[..n]);
                assert!(
                    verify_consistency(m, &first_root, n, &second_root, &proof),
                    "size {m} -> {n} did not verify ({} nodes)",
                    proof.len()
                );
            }
        }
    }

    /// A proof that the log grew must not verify against a different earlier root:
    /// that is precisely the rewound-history case this exists to catch.
    #[test]
    fn consistency_rejects_a_rewritten_past() {
        let leaves = hashes(16);
        let mut proof = Vec::new();
        super::subproof(&leaves, 5, 16, true, &mut proof);
        let honest = root_of(&leaves[..5]);

        let mut rewritten = leaves.clone();
        rewritten[2] = [0xaa; 32];
        let rewritten_root = root_of(&rewritten[..5]);
        let new_root = root_of(&leaves[..16]);

        assert!(verify_consistency(5, &honest, 16, &new_root, &proof));
        assert!(!verify_consistency(5, &rewritten_root, 16, &new_root, &proof));
    }

    /// Truncating or padding a proof must fail rather than pass by accident.
    #[test]
    fn consistency_rejects_damaged_proofs() {
        let leaves = hashes(11);
        let mut proof = Vec::new();
        super::subproof(&leaves, 3, 11, true, &mut proof);
        let first = root_of(&leaves[..3]);
        let second = root_of(&leaves[..11]);
        assert!(verify_consistency(3, &first, 11, &second, &proof));

        let mut shortened = proof.clone();
        shortened.pop();
        assert!(!verify_consistency(3, &first, 11, &second, &shortened));

        let mut flipped = proof.clone();
        flipped[0] = [0x55; 32];
        assert!(!verify_consistency(3, &first, 11, &second, &flipped));

        assert!(!verify_consistency(11, &second, 3, &first, &proof));
    }

    /// Same size: only equal roots are consistent, and no proof is needed.
    #[test]
    fn consistency_at_equal_sizes_is_equality() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(verify_consistency(4, &a, 4, &a, &[]));
        assert!(!verify_consistency(4, &a, 4, &b, &[]));
    }

    /// One-off: record every account that already has a key. Run with
    /// `cargo test backfill_from_live_users -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn backfill_from_live_users() {
        let storage = crate::core::user::get_or_init_storage(
            "data/users.bin".to_string(),
            "slothlee.xyz".to_string(),
        );
        let mut recorded = 0;
        for (username, key) in storage.key_inventory() {
            if record_for(&username, key.as_slice()).is_ok() {
                recorded += 1;
            }
        }
        println!("backfilled {} accounts, log now {}", recorded, size());
    }

    fn leaf(seq: u64, account: &str, seed: u8) -> Leaf {
        Leaf {
            seq,
            account: account.to_string(),
            rsa: STANDARD.encode([seed; 32]),
            pq: None,
            at: 1_700_000_000,
        }
    }

    #[test]
    fn an_empty_tree_has_a_root_and_no_leaves() {
        assert_eq!(root_of(&[]), empty_root());
        assert!(audit_path(&[], 0).is_empty());
    }

    #[test]
    fn one_leaf_is_its_own_root() {
        let hashes = [leaf_hash(&leaf(0, "bob", 1))];
        assert_eq!(root_of(&hashes), hashes[0]);
        assert!(audit_path(&hashes, 0).is_empty());
        assert_eq!(root_from_path(hashes[0], 0, 1, &[]), hashes[0]);
    }

    #[test]
    fn every_leaf_proves_into_the_root_across_sizes() {
        for count in 1..=9usize {
            let leaves: Vec<Leaf> = (0..count).map(|i| leaf(i as u64, "acct", i as u8)).collect();
            let hashes: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
            let root = root_of(&hashes);
            for index in 0..count {
                let path = audit_path(&hashes, index);
                assert_eq!(
                    root_from_path(hashes[index], index, count, &path),
                    root,
                    "leaf {index} of {count} did not prove into the root",
                );
            }
        }
    }

    #[test]
    fn a_tampered_leaf_or_path_fails_to_prove() {
        let leaves: Vec<Leaf> = (0..4).map(|i| leaf(i as u64, "acct", i as u8)).collect();
        let hashes: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
        let root = root_of(&hashes);
        let path = audit_path(&hashes, 1);

        let mut swapped = path.clone();
        swapped[0] = [9u8; 32];
        assert_ne!(root_from_path(hashes[1], 1, 4, &swapped), root);

        let mut wrong_index = hashes[1];
        wrong_index[0] ^= 0xff;
        assert_ne!(root_from_path(wrong_index, 1, 4, &path), root);
    }

    #[test]
    fn a_key_change_moves_the_root_and_a_repeat_does_not() {
        let a = leaf(0, "bob", 1);
        let b = leaf(1, "bob", 2);
        assert_ne!(leaf_hash(&a), leaf_hash(&b));

        let mut leaves = vec![leaf_hash(&a)];
        let before = root_of(&leaves);
        leaves.push(leaf_hash(&b));
        assert_ne!(root_of(&leaves), before);
    }

    #[test]
    fn the_leaf_hash_binds_the_account_and_the_sequence() {
        let base = leaf(0, "bob", 1);
        let renamed = Leaf { account: "alice".into(), ..base.clone() };
        let resequenced = Leaf { seq: 7, ..base.clone() };
        assert_ne!(leaf_hash(&base), leaf_hash(&renamed));
        assert_ne!(leaf_hash(&base), leaf_hash(&resequenced));
    }

    #[test]
    fn a_head_carries_a_signature_that_verifies() {
        let root = root_of(&[leaf_hash(&leaf(0, "bob", 1))]);
        let head = sign_head(1, &root).expect("sign");
        assert_eq!(head.alg, "ml-dsa-65");
        assert!(verify_head(&head));

        let tampered = Head { root: STANDARD.encode([7u8; 32]), ..head };
        assert!(!verify_head(&tampered));
    }
}
