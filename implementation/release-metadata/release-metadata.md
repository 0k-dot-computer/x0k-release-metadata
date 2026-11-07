# x0k-release-metadata: verifying a release against its maintainers

```turtle folio:document
implementation:release-metadata\/release-metadata a x0k:Implementation ;
    x0k:status "draft" ;
    x0k:summary "The TUF metadata types with signatory, custody and presence-flag fields, TUF's ed25519 scheme and the four SSHSIG schemes (an SSH key, a Secure Enclave key, a FIDO2 token, a passkey through WebAuthn), and a pure verifier that walks TUF's client workflow and counts signatories, not keys." ;
    x0k:concerns "trust", "delivery", "signing", "keys", "publication" ;
    x0k:cites architecture:service-authorization,
        publication:x0k-release-metadata,
        implementation:release-metadata\/vectors,
        implementation:release-metadata\/ceremony ;
    x0k:implements design:distribution-and-updates ;
    x0k:motivatedBy architecture:release-metadata ;
    folio:tangleCrate "crates/x0k-release-metadata" ;
    folio:tangleRoot "src/lib.rs" .
```

A user's machine downloads a release from servers it does not trust. It
must decide, from bytes alone, that enough of the publisher's maintainers
signed this artifact for this machine's audience, and that nobody served an
old or withheld release instead. This crate makes that decision. It is one
function, `verify`, with five inputs: the reader's trusted state, the
metadata the embedder fetched, a target path, the length and hashes of the
downloaded artifact, and the current time. Out comes the verified target and
the new trusted state, or a `Refusal` that names the role, the rule and the
signatories.

The record layout and the client workflow are TUF's (specification 1.0.37),
as `x0k:architecture/release-metadata` §1 decides. The crate adds two things
to TUF. A threshold counts **signatories**, the people who may sign, and not
keys (§4). A signature may also be an **SSHSIG** envelope, so keys that an
SSH agent holds can sign (§3). A repository that uses neither addition is
plain TUF, and this verifier reads it the way a TUF client does.

The carried example is chariot's root. Alice and Bob are its maintainers.
Alice holds two keys, a laptop key and a FIDO2 token; Bob holds one. The
root delegates two audiences: `fleet`, the maintainers' own machines, and
`pilot`, the machines of pilot users. Carol's key is an SSH key. The
conformance vectors (`implementation:release-metadata/vectors`) build every
case from this cast.

## What the crate adopts, and what it writes itself

`tough`, AWS's Rust TUF implementation, was the first candidate
(`principle:adopt-before-invent`). Its types do not fit. Its key type is a
closed enum of RSA, Ed25519 and ECDSA keys, so neither the signatory field
nor an SSHSIG scheme can be added without a fork. Its client is
asynchronous and always depends on `tokio`, `rustls`, `aws-lc-rs` and `url`,
so a dependency check could not show that the verifier opens no connection
(§7). The crate adopts the parts of tough's stack that are small and
exact instead:

- **`olpc-cjson`**, tough's own canonical-JSON formatter for `serde_json`.
  TUF signs the canonical form of the `signed` body, and this formatter
  writes it.
- **`ed25519-dalek`** for Ed25519 signatures, TUF's own scheme and the SSH
  and FIDO2 ones.
- **`p256`**, RustCrypto's P-256 crate, for ECDSA signatures: a Secure
  Enclave key, a FIDO2 `ecdsa-sk` token and a passkey.
- **`base64ct`** for the base64 of an SSH key line and of a WebAuthn
  challenge.

The SSHSIG envelope and the OpenSSH wire format around it are the crate's
own, about a hundred lines ("Schemes"): RustCrypto's `ssh-key` lacks the
WebAuthn signature type and re-encodes an `sk-ecdsa` signature
differently from OpenSSH. The tests and the vector generator still use
`ssh-key` to sign with software SSH keys. No program runs to verify.

The metadata types and the workflow are this crate's own, about a thousand
lines. They follow the specification's sections one to one, and each
section is cited where its code is.

## The contract

The verifier performs no I/O. It opens no file and no connection, spawns
nothing and reads no clock: the embedder passes the time in, and the test
`tests/conformance/purity.rs` checks the sources for each of these. The
ceremony commands of §5 (`implementation:release-metadata/ceremony`) are
the crate's one exception: they run the signer program they are given, and
only `src/signer.rs` and the command-line program do that. The crate depends on
no x0k crate and on no git source, so chariot takes it from crates.io.

<a name="chunk-lib"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#lib`</sub>

```rust {#lib file="src/lib.rs"}
//! Verifies a release against the root of trust its maintainers sign.
//!
//! The metadata is TUF's (specification 1.0.37) in TUF's canonical JSON.
//! A threshold counts signatories, not keys. [`verify`] is a pure
//! function: it performs no I/O and reads no clock.

#![allow(
    clippy::result_large_err,
    reason = "a Refusal is what a failed update returns, once per call, and boxing it would make every caller dereference it for no measured gain"
)]

mod canonical;
mod ceremony;
mod metadata;
mod quorum;
mod refusal;
mod scheme;
mod signer;
mod time;
mod verify;

pub use canonical::{canonical_json, key_id};
pub use ceremony::{sign, sign_snapshot, sign_timestamp, stage, CeremonyError, Rebuild, Requirement, Standing};
pub use metadata::{
    Custody, DelegatedRole, Delegations, Key, KeyVal, ListedKey, MetaFile, PresenceFlag, RoleKeys,
    Root, SignatoryRule, Snapshot, TargetEntry, Targets, Timestamp,
};
pub use refusal::{Malformed, Refusal, Rule, SignatoryVerdict, SignatureFault};
pub use signer::{Signer, SignerError, SignerProgram};
pub use time::parse_utc;
pub use verify::{verify, Artifact, Fetched, TrustedState, Verified, VerifiedTarget};

/// The SSHSIG namespace every release-metadata signature is made under.
pub const NAMESPACE: &str = "release-metadata";
```

Every failure is a `Refusal`. It carries the role whose check failed, the
rule, and for a threshold the standing of each signatory the role lists.
That makes it larger than clippy's `result_large_err` threshold of 128
bytes, and the crate allows the lint: a refusal is returned once, at the
end of a failed update, so its size costs nothing a caller would measure,
while a boxed refusal would make every caller dereference it.
§4 asks that the verifier name each signatory that signed but did not count,
and why. A `SignatoryVerdict` says how many of their keys verified, how
many their rule requires, and which of their signatures failed and how.

<a name="chunk-refusal"></a><sub>[`src/refusal.rs`](../../crates/x0k-release-metadata/src/refusal.rs) · `#refusal` · assembles [rule](#chunk-rule) · [signature-fault](#chunk-signature-fault) · [malformed](#chunk-malformed)</sub>

```rust {#refusal file="src/refusal.rs"}
/// Why the verifier refused an update: the role whose check failed, the
/// rule, and how each signatory of that role stood.
#[derive(Debug, thiserror::Error)]
#[error("{role}: {rule}")]
pub struct Refusal {
    pub role: String,
    pub rule: Rule,
    /// Every signatory the role lists, for a threshold refusal.
    pub signatories: Vec<SignatoryVerdict>,
    /// Key ids that signed but that the role does not list.
    pub unlisted_keys: Vec<String>,
}

impl Refusal {
    pub(crate) fn new(role: &str, rule: impl Into<Rule>) -> Self {
        Self {
            role: role.to_owned(),
            rule: rule.into(),
            signatories: Vec::new(),
            unlisted_keys: Vec::new(),
        }
    }
}

/// How one signatory of a role stood when the role's signatures were counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatoryVerdict {
    pub signatory: String,
    pub valid_keys: u64,
    pub required_keys: u64,
    pub counted: bool,
    /// Signatures by this signatory's keys that did not verify, by key id.
    pub faults: Vec<(String, SignatureFault)>,
}

<<rule>>

<<signature-fault>>

<<malformed>>
```

The rules follow the client workflow's checks. Each has a short code, which
the conformance vectors use to name the refusal they expect.

<a name="chunk-rule"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#rule`</sub>

```rust {#rule}
/// The check that failed.
#[derive(Debug, thiserror::Error)]
pub enum Rule {
    #[error("{counted} of {threshold} signatories counted")]
    Threshold { threshold: u64, counted: u64 },
    #[error("{counted} of the {threshold} signatories of root version {keys_of} signed")]
    RootThreshold { keys_of: u64, threshold: u64, counted: u64 },
    #[error("root version {offered} does not follow trusted version {trusted}")]
    RootSequence { trusted: u64, offered: u64 },
    #[error("version {offered} is lower than trusted version {trusted}")]
    Rollback { trusted: u64, offered: u64 },
    #[error("version {offered} differs from version {listed} that {lister} lists")]
    VersionMismatch { lister: String, listed: u64, offered: u64 },
    #[error("{lister} does not list this role")]
    Unlisted { lister: String },
    #[error("the new snapshot drops {file}, which the trusted snapshot lists")]
    SnapshotDropsRole { file: String },
    #[error("expired at {expires}")]
    Expired { expires: String },
    #[error("the {algorithm} hash differs from the one {lister} lists")]
    HashMismatch { lister: String, algorithm: String },
    #[error("length {offered} differs from length {listed} that {lister} lists")]
    LengthMismatch { lister: String, listed: u64, offered: u64 },
    #[error("no supplied hash uses an algorithm {lister} lists")]
    NoCommonHash { lister: String },
    #[error("the embedder supplied no metadata for this role")]
    Missing,
    #[error("{counted} of the {signatories} signatories signed a delegation for a public audience, which needs every one")]
    PublicDelegation { signatories: u64, counted: u64 },
    #[error("no delegation lists target {path}")]
    UnknownTarget { path: String },
    #[error("malformed: {0}")]
    Malformed(#[from] Malformed),
}

impl Rule {
    /// The rule's short code, as the conformance vectors spell it.
    pub fn code(&self) -> &'static str {
        match self {
            Rule::Threshold { .. } => "threshold",
            Rule::RootThreshold { .. } => "root-threshold",
            Rule::RootSequence { .. } => "root-sequence",
            Rule::Rollback { .. } => "rollback",
            Rule::VersionMismatch { .. } => "version-mismatch",
            Rule::Unlisted { .. } => "unlisted",
            Rule::SnapshotDropsRole { .. } => "snapshot-drops-role",
            Rule::Expired { .. } => "expired",
            Rule::HashMismatch { .. } => "hash-mismatch",
            Rule::LengthMismatch { .. } => "length-mismatch",
            Rule::NoCommonHash { .. } => "no-common-hash",
            Rule::Missing => "missing",
            Rule::PublicDelegation { .. } => "public-delegation",
            Rule::UnknownTarget { .. } => "unknown-target",
            Rule::Malformed(_) => "malformed",
        }
    }
}
```

§3 names the three reasons a signature does not count: another namespace,
an unknown scheme, or a key the role does not list. The last is not a fault
of the signature, so it goes in `Refusal::unlisted_keys`. The others, and a
signature that does not verify, are faults.

<a name="chunk-signature-fault"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#signature-fault`</sub>

```rust {#signature-fault}
/// Why one signature did not count.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureFault {
    #[error("unknown scheme {0}")]
    UnknownScheme(String),
    #[error("the public key is malformed for its scheme")]
    Key,
    #[error("the signature is not encoded as its scheme requires")]
    Encoding,
    #[error("signed under namespace {0}")]
    Namespace(String),
    #[error("the signature does not verify")]
    Invalid,
    #[error("the signature lacks the {0} flag that the signatory's rule demands")]
    MissingFlag(&'static str),
    #[error("the WebAuthn client data does not carry this message as its challenge")]
    ClientData,
}
```

A file that does not parse, or that breaks a rule of the format itself, is
malformed. One case guards §4 directly: two key ids with the same public
key. A key id covers the whole key object, signatory field included, so
one key listed twice under two signatories would have two ids. One
signature would then count for two people. The verifier refuses such a key
listing, and it compares the keys themselves, so an Ed25519 key listed once
in TUF's hex form and once as an SSH key line is one key.

<a name="chunk-malformed"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#malformed`</sub>

```rust {#malformed}
/// A metadata file that breaks the format.
#[derive(Debug, thiserror::Error)]
pub enum Malformed {
    #[error("not the expected JSON: {0}")]
    Json(#[source] serde_json::Error),
    #[error("cannot be written as canonical JSON: {0}")]
    Canonical(#[source] serde_json::Error),
    #[error("_type is {found}, expected {expected}")]
    WrongType { expected: &'static str, found: String },
    #[error("key id {listed} is not the SHA-256 of its key's canonical form")]
    KeyId { listed: String },
    #[error("key ids {first} and {second} list one public key")]
    DuplicateKey { first: String, second: String },
    #[error("role {role} lists key {keyid}, which the key listing lacks")]
    UnknownKeyId { role: String, keyid: String },
    #[error("role {role} has a threshold of zero")]
    ZeroThreshold { role: String },
    #[error("signatory {signatory} requires zero keys")]
    ZeroKeysRequired { signatory: String },
    #[error("signatory {signatory}'s rule demands presence flags, but key {keyid} signs without them")]
    PresenceWithoutFlags { signatory: String, keyid: String },
    #[error("root lists no {role} role")]
    MissingRole { role: String },
    #[error("a delegation names the top-level role {0}")]
    ReservedRoleName(String),
    #[error("date-time {0} is not of the form YYYY-MM-DDTHH:MM:SSZ")]
    DateTime(String),
    #[error("unsupported hash algorithm {0}")]
    HashAlgorithm(String),
}
```

## Canonical JSON

TUF signs the canonical form of a file's `signed` body (§ "Metaformat").
The verifier must check the signatures over exactly what the signers saw. It
does not deserialize the body into typed structs and serialize it again,
because that drops every field the structs do not name, and an extended
body would no longer verify. It reads the body as a JSON value, writes that
value canonically, and checks the signatures over those bytes. The typed
body is read from the same value, so what is checked and what is used are
one parse.

<a name="chunk-canonical"></a><sub>[`src/canonical.rs`](../../crates/x0k-release-metadata/src/canonical.rs) · `#canonical` · assembles [envelope](#chunk-envelope)</sub>

```rust {#canonical file="src/canonical.rs"}
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::metadata::Typed;
use crate::Malformed;

/// Writes a JSON value in TUF's canonical form (OLPC canonical JSON).
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, Malformed> {
    let mut out = Vec::new();
    let formatter = olpc_cjson::CanonicalFormatter::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    value
        .serialize(&mut serializer)
        .map_err(Malformed::Canonical)?;
    Ok(out)
}

/// A TUF key id: the lowercase hex SHA-256 of the key object's canonical form.
pub fn key_id(key: &Value) -> Result<String, Malformed> {
    Ok(hex::encode(Sha256::digest(canonical_json(key)?)))
}

<<envelope>>
```

A metadata file is an envelope of the body and its signatures. Opening one
yields the typed body, the canonical bytes its signatures cover, and the
signatures, after checking that `_type` names the role kind the caller
expects.

<a name="chunk-envelope"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#envelope`</sub>

```rust {#envelope}
/// One entry of a metadata file's `signatures` list.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Signature {
    pub keyid: String,
    pub sig: String,
}

/// A metadata file as read off the wire.
pub(crate) struct Envelope<T> {
    pub body: T,
    pub canonical: Vec<u8>,
    pub signatures: Vec<Signature>,
}

#[derive(Deserialize)]
struct Wire {
    signed: Value,
    signatures: Vec<Signature>,
}

pub(crate) fn open_envelope<T: DeserializeOwned + Typed>(bytes: &[u8]) -> Result<Envelope<T>, Malformed> {
    let wire: Wire = serde_json::from_slice(bytes).map_err(Malformed::Json)?;
    let canonical = canonical_json(&wire.signed)?;
    let body: T = serde_json::from_value(wire.signed).map_err(Malformed::Json)?;
    if body.kind() != T::TYPE {
        return Err(Malformed::WrongType {
            expected: T::TYPE,
            found: body.kind().to_owned(),
        });
    }
    Ok(Envelope {
        body,
        canonical,
        signatures: wire.signatures,
    })
}
```

## The four roles

The types follow TUF's § "Document formats" field for field. Unknown fields
are ignored when a body is read, and they stay covered by the signatures,
as the previous section shows.

<a name="chunk-metadata"></a><sub>[`src/metadata.rs`](../../crates/x0k-release-metadata/src/metadata.rs) · `#metadata` · assembles [key](#chunk-key) · [root](#chunk-root) · [targets](#chunk-targets) · [snapshot-timestamp](#chunk-snapshot-timestamp)</sub>

```rust {#metadata file="src/metadata.rs"}
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::key_id;

/// A metadata body with a `_type` and an expiry.
pub(crate) trait Typed {
    const TYPE: &'static str;
    fn kind(&self) -> &str;
    fn expires(&self) -> &str;
}

macro_rules! typed {
    ($ty:ty, $name:literal) => {
        impl Typed for $ty {
            const TYPE: &'static str = $name;
            fn kind(&self) -> &str {
                &self.kind
            }
            fn expires(&self) -> &str {
                &self.expires
            }
        }
    };
}

typed!(Root, "root");
typed!(Targets, "targets");
typed!(Snapshot, "snapshot");
typed!(Timestamp, "timestamp");

<<key>>

<<root>>

<<targets>>

<<snapshot-timestamp>>
```

A key object keeps TUF's `keytype`, `scheme` and `keyval`. It adds the two
fields of §4: `x-release-metadata-signatory`, the maintainer who holds the
key, and `x-release-metadata-custody`, where they say it is kept. The
prefix keeps them apart from any field a later TUF version adds. Both are
optional. A key that names no signatory is its own signatory, named by its
key id, so a plain TUF root counts keys exactly as TUF does. The `keyval`
of each scheme is in the next section.

<a name="chunk-key"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#key`</sub>

```rust {#key}
/// A TUF key object, with the signatory who holds it and its custody.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Key {
    pub keytype: String,
    pub scheme: String,
    pub keyval: KeyVal,
    #[serde(default, rename = "x-release-metadata-signatory")]
    pub signatory: Option<String>,
    #[serde(default, rename = "x-release-metadata-custody")]
    pub custody: Option<Custody>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct KeyVal {
    pub public: String,
}

/// Where a key is kept: a claim the root makes, not a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Custody {
    Fido2,
    SecureEnclave,
    Passkey,
    Software,
}
```

TUF requires that a client compute each key id and check it against the
key (§ "File formats: root.json"). A listed key therefore remembers the id
its own canonical form hashes to, computed from the value as read, so the
extension fields are part of the id.

<a name="chunk-key-2"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#key` · continues</sub>

```rust {#key}

/// A key as a key listing holds it, with the id its canonical form hashes to.
#[derive(Debug, Clone)]
pub struct ListedKey {
    pub key: Key,
    pub(crate) computed_id: String,
}

impl<'de> Deserialize<'de> for ListedKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Value::deserialize(deserializer)?;
        let computed_id = key_id(&raw).map_err(serde::de::Error::custom)?;
        let key = Key::deserialize(raw).map_err(serde::de::Error::custom)?;
        Ok(Self { key, computed_id })
    }
}
```

The root names the keys and a threshold for each top-level role. It also
holds each signatory's rule (§4), in `x-release-metadata-signatories`: how
many of their keys that a role lists must sign before they count, one when
the root names no rule. And it names the audiences that are public, in
`x-release-metadata-public-audiences` (§8): a targets file of such an
audience that delegates needs every signatory its role lists. Presence
flags join the rule when hardware schemes arrive.

<a name="chunk-root"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#root`</sub>

```rust {#root}
/// `root.json`: the keys and threshold of each top-level role, and each
/// signatory's rule.
#[derive(Debug, Clone, Deserialize)]
pub struct Root {
    #[serde(rename = "_type")]
    pub kind: String,
    pub spec_version: String,
    #[serde(default)]
    pub consistent_snapshot: bool,
    pub version: u64,
    pub expires: String,
    pub keys: BTreeMap<String, ListedKey>,
    pub roles: BTreeMap<String, RoleKeys>,
    #[serde(default, rename = "x-release-metadata-signatories")]
    pub signatories: BTreeMap<String, SignatoryRule>,
    /// The audiences whose delegations need every signatory (decision §8).
    #[serde(default, rename = "x-release-metadata-public-audiences")]
    pub public_audiences: BTreeSet<String>,
}

/// The keys that may sign a role, and how many signatories must.
#[derive(Debug, Clone, Deserialize)]
pub struct RoleKeys {
    pub keyids: Vec<String>,
    pub threshold: u64,
}

/// A signatory's rule: how many of their listed keys must sign, and the
/// flags each of those signatures must carry.
#[derive(Debug, Clone, Deserialize)]
pub struct SignatoryRule {
    #[serde(default = "default_keys_required")]
    pub keys_required: u64,
    #[serde(default)]
    pub flags: Vec<PresenceFlag>,
}

/// A flag that a FIDO2 or WebAuthn signature carries (OpenSSH PROTOCOL.u2f).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresenceFlag {
    /// A person touched the token: flag `0x01`.
    UserPresent,
    /// The token verified the person by PIN or biometric: flag `0x04`.
    UserVerified,
}

impl PresenceFlag {
    pub fn bit(self) -> u8 {
        match self {
            Self::UserPresent => 0x01,
            Self::UserVerified => 0x04,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::UserPresent => "user-present",
            Self::UserVerified => "user-verified",
        }
    }
}

fn default_keys_required() -> u64 {
    1
}
```

A targets file lists artifacts by length and hashes, and may delegate
paths to further roles (§ "File formats: targets.json and delegated target
roles"). An audience is one such delegation (decision §2).

<a name="chunk-targets"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#targets` · assembles [covers](#chunk-covers)</sub>

```rust {#targets}
/// `targets.json`, or a delegated targets role.
#[derive(Debug, Clone, Deserialize)]
pub struct Targets {
    #[serde(rename = "_type")]
    pub kind: String,
    pub spec_version: String,
    pub version: u64,
    pub expires: String,
    pub targets: BTreeMap<String, TargetEntry>,
    #[serde(default)]
    pub delegations: Option<Delegations>,
}

impl Targets {
    /// Whether this file delegates any path to a further role.
    pub(crate) fn delegates(&self) -> bool {
        self.delegations.as_ref().is_some_and(|d| !d.roles.is_empty())
    }
}

/// One artifact: its length and its hashes, by algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TargetEntry {
    pub length: u64,
    pub hashes: BTreeMap<String, String>,
}

/// The roles a targets role delegates to, in priority order, and their keys.
#[derive(Debug, Clone, Deserialize)]
pub struct Delegations {
    pub keys: BTreeMap<String, ListedKey>,
    pub roles: Vec<DelegatedRole>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DelegatedRole {
    pub name: String,
    pub keyids: Vec<String>,
    pub threshold: u64,
    #[serde(default)]
    pub terminating: bool,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub path_hash_prefixes: Option<Vec<String>>,
}

<<covers>>
```

A delegation covers a path by its patterns or by prefixes of the path's
SHA-256. TUF's patterns are shell globs in which a wildcard never matches
the separator `/`. So a pattern matches only a path with as many segments.
An audience's targets are flat (decision §2): a path is the audience's
name, a `/` and a file name, such as `fleet/chariot-1.0.tar`, and the
audience's delegation is the one pattern `fleet/*`. The lookup refuses a
deeper path before it reads any targets file (below).

<a name="chunk-covers"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#covers`</sub>

```rust {#covers}
impl DelegatedRole {
    /// Whether this delegation covers `path`.
    pub fn covers(&self, path: &str) -> bool {
        if let Some(patterns) = &self.paths {
            return patterns.iter().any(|pattern| pattern_covers(pattern, path));
        }
        if let Some(prefixes) = &self.path_hash_prefixes {
            let digest = hex::encode(Sha256::digest(path.as_bytes()));
            return prefixes.iter().any(|prefix| digest.starts_with(prefix.as_str()));
        }
        false
    }
}

fn pattern_covers(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    pattern.len() == path.len()
        && pattern
            .iter()
            .zip(&path)
            .all(|(p, s)| segment_matches(p.as_bytes(), s.as_bytes()))
}

fn segment_matches(pattern: &[u8], segment: &[u8]) -> bool {
    match (pattern.split_first(), segment.split_first()) {
        (None, None) => true,
        (Some((b'*', rest)), _) => {
            segment_matches(rest, segment)
                || (!segment.is_empty() && segment_matches(pattern, &segment[1..]))
        }
        (Some((b'?', rest)), Some((_, tail))) => segment_matches(rest, tail),
        (Some((p, rest)), Some((s, tail))) if p == s => segment_matches(rest, tail),
        _ => false,
    }
}
```

The snapshot lists the version of every targets file; the timestamp lists
the snapshot. Each listing may also give a length and hashes.

<a name="chunk-snapshot-timestamp"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#snapshot-timestamp`</sub>

```rust {#snapshot-timestamp}
/// `snapshot.json`: the version of every targets file.
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "_type")]
    pub kind: String,
    pub spec_version: String,
    pub version: u64,
    pub expires: String,
    pub meta: BTreeMap<String, MetaFile>,
}

/// `timestamp.json`: the current snapshot.
#[derive(Debug, Clone, Deserialize)]
pub struct Timestamp {
    #[serde(rename = "_type")]
    pub kind: String,
    pub spec_version: String,
    pub version: u64,
    pub expires: String,
    pub meta: BTreeMap<String, MetaFile>,
}

/// One listed metadata file: its version, and optionally its length and hashes.
#[derive(Debug, Clone, Deserialize)]
pub struct MetaFile {
    pub version: u64,
    #[serde(default)]
    pub length: Option<u64>,
    #[serde(default)]
    pub hashes: Option<BTreeMap<String, String>>,
}
```

## Time is an input

TUF writes an expiry as `YYYY-MM-DDTHH:MM:SSZ` (§ "Date-time"). The crate
parses that one form itself, in a few lines, rather than take a date crate
for it, and writes it back the same way for the snapshots and timestamps
it signs. The current time arrives as a `SystemTime` that the embedder read,
and a file is expired when its expiry is not later than that time.

<a name="chunk-time"></a><sub>[`src/time.rs`](../../crates/x0k-release-metadata/src/time.rs) · `#time`</sub>

```rust {#time file="src/time.rs"}
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Malformed;

/// Parses TUF's date-time form, `YYYY-MM-DDTHH:MM:SSZ`, in UTC.
pub fn parse_utc(text: &str) -> Result<SystemTime, Malformed> {
    let bad = || Malformed::DateTime(text.to_owned());
    let b = text.as_bytes();
    let shaped = b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z';
    if !shaped {
        return Err(bad());
    }
    let field = |from: usize, to: usize| {
        text.get(from..to)
            .filter(|s| s.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(bad)
    };
    let (year, month, day) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (hour, minute, second) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(bad());
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    let seconds = u64::try_from(seconds).map_err(|_| bad())?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn days_in_month(year: i64, month: i64) -> i64 {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Writes a time in TUF's date-time form, to the second, as the online
/// roles' expiry.
pub(crate) fn format_utc(time: SystemTime) -> Result<String, Malformed> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .ok_or_else(|| Malformed::DateTime(format!("{time:?}")))?;
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rest / 3_600, rest % 3_600 / 60, rest % 60);
    Ok(format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"))
}

/// The date `days` after 1970-01-01, the inverse of `days_from_civil`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    (year_of_era + era * 400 + i64::from(month <= 2), month, day)
}

/// Days from 1970-01-01 to a date in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}
```

## Schemes

A scheme says how a key signs. The crate verifies five, all in process
(§3):

| Scheme | `keytype` | Signer |
|---|---|---|
| `ed25519` | `ed25519` | TUF's own: a software key |
| `sshsig-ssh-ed25519` | `ssh-ed25519` | A software key, or an x0k device key |
| `sshsig-ecdsa-sha2-nistp256` | `ecdsa-sha2-nistp256` | A Secure Enclave key through Secretive |
| `sshsig-sk-ssh-ed25519` | `sk-ssh-ed25519@openssh.com` | A FIDO2 token |
| `sshsig-sk-ecdsa-sha2-nistp256` | `sk-ecdsa-sha2-nistp256@openssh.com` | A FIDO2 token, or a passkey through WebAuthn |

TUF's `ed25519` key holds the raw 32-byte public key in hex, and its
signature is a raw Ed25519 signature over the canonical bytes, in hex.

Every other scheme is an SSHSIG envelope (OpenSSH `PROTOCOL.sshsig`) over
the canonical bytes, under the namespace `release-metadata`. The key
object holds the public key as `ssh-keygen` prints it, with no comment
(`sk-ssh-ed25519@openssh.com AAAAGnNr…`), and its `keytype` is that line's
key type. The `sig` field holds the envelope's binary encoding in
lowercase hex, the bytes inside the armor that `ssh-keygen -Y sign`
writes. The line names its key type, so a scheme adds a name and no field.
A key line that carries a comment, or whose key type differs from
`keytype` or from the scheme's, is a malformed key, and its signatures do
not count. Any other scheme is a fault of that one signature, and it does
not count. A role whose threshold the remaining signatures meet still
verifies.

<a name="chunk-scheme"></a><sub>[`src/scheme.rs`](../../crates/x0k-release-metadata/src/scheme.rs) · `#scheme` · assembles [ssh-wire](#chunk-ssh-wire) · [ssh-keys](#chunk-ssh-keys) · [check-sshsig](#chunk-check-sshsig) · [sk-signatures](#chunk-sk-signatures)</sub>

```rust {#scheme file="src/scheme.rs"}
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

use crate::{Key, SignatureFault, NAMESPACE};

/// Checks one signature by `key` over `message`, in the key's scheme, and
/// returns the flags an `sk` signature carries.
pub(crate) fn check_signature(key: &Key, message: &[u8], sig_hex: &str) -> Result<Option<u8>, SignatureFault> {
    match key.scheme.as_str() {
        "ed25519" if key.keytype == "ed25519" => check_ed25519(key, message, sig_hex).map(|()| None),
        "ed25519" => Err(SignatureFault::Key),
        scheme => match SshKeyType::of_scheme(scheme) {
            Some(keytype) => check_sshsig(key, keytype, message, sig_hex),
            None => Err(SignatureFault::UnknownScheme(scheme.to_owned())),
        },
    }
}

/// Whether a key's signatures carry the flags a presence rule reads (§4).
pub(crate) fn proves_presence(key: &Key) -> bool {
    SshKeyType::of_scheme(&key.scheme).is_some_and(SshKeyType::is_sk)
}

fn ed25519_public(key: &Key) -> Result<[u8; 32], SignatureFault> {
    let bytes = hex::decode(&key.keyval.public).map_err(|_| SignatureFault::Key)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| SignatureFault::Key)
}

fn check_ed25519(key: &Key, message: &[u8], sig_hex: &str) -> Result<(), SignatureFault> {
    let signature = hex::decode(sig_hex).map_err(|_| SignatureFault::Encoding)?;
    verify_ed25519(&ed25519_public(key)?, message, &signature)
}

fn verify_ed25519(public: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<(), SignatureFault> {
    let public = VerifyingKey::from_bytes(public).map_err(|_| SignatureFault::Key)?;
    let signature = Ed25519Signature::from_slice(signature).map_err(|_| SignatureFault::Encoding)?;
    public
        .verify_strict(message, &signature)
        .map_err(|_| SignatureFault::Invalid)
}

<<ssh-wire>>

<<ssh-keys>>

<<check-sshsig>>

<<sk-signatures>>
```

The crate reads OpenSSH's wire format itself. It is a few kinds of field,
a byte, a big-endian `u32` and a length-prefixed string, and reading it
here keeps every SSHSIG form on one path. RustCrypto's `ssh-key` was the
first choice for the envelope, but it has no WebAuthn signature type, and
it writes an `sk-ecdsa` signature's flags and counter inside the
signature string, where OpenSSH puts them after it.

<a name="chunk-ssh-wire"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#ssh-wire`</sub>

```rust {#ssh-wire}
/// A reader over OpenSSH's wire encoding.
pub(crate) struct Wire<'a> {
    rest: &'a [u8],
}

impl<'a> Wire<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.rest.split_at_checked(len)?;
        self.rest = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.bytes(4).and_then(|b| b.try_into().ok()).map(u32::from_be_bytes)
    }

    pub(crate) fn string(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32()?).ok()?;
        self.bytes(len)
    }

    /// Ends the read; `None` when bytes are left over.
    fn finish(self) -> Option<()> {
        self.rest.is_empty().then_some(())
    }
}

/// Appends a length-prefixed string.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend(bytes);
}
```

An SSH key line is the key type, a space and the base64 of the key's wire
encoding. The check decodes the base64 and encodes it again, so a comment,
stray whitespace or a non-canonical encoding makes the key malformed. The
wire encoding names the key type again, then holds the key: a 32-byte
Ed25519 key, or a curve name and a P-256 point. An `sk` key also holds the
application string that its token signs over, `ssh:` by default for a
FIDO2 token and the relying party's id for a passkey.

<a name="chunk-ssh-keys"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#ssh-keys`</sub>

```rust {#ssh-keys}
/// The SSH key types the `sshsig-` schemes name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshKeyType {
    Ed25519,
    EcdsaP256,
    SkEd25519,
    SkEcdsaP256,
}

impl SshKeyType {
    fn of_scheme(scheme: &str) -> Option<Self> {
        Some(match scheme {
            "sshsig-ssh-ed25519" => Self::Ed25519,
            "sshsig-ecdsa-sha2-nistp256" => Self::EcdsaP256,
            "sshsig-sk-ssh-ed25519" => Self::SkEd25519,
            "sshsig-sk-ecdsa-sha2-nistp256" => Self::SkEcdsaP256,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
            Self::SkEd25519 => "sk-ssh-ed25519@openssh.com",
            Self::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    fn is_sk(self) -> bool {
        matches!(self, Self::SkEd25519 | Self::SkEcdsaP256)
    }
}

/// An SSH public key: its wire encoding, and what verifying needs.
struct SshPublic {
    wire: Vec<u8>,
    material: Material,
}

enum Material {
    Ed25519([u8; 32]),
    EcdsaP256(P256VerifyingKey),
    SkEd25519 { key: [u8; 32], application: Vec<u8> },
    SkEcdsaP256 { key: P256VerifyingKey, application: Vec<u8> },
}

/// The public key of an SSHSIG key object, whose line must be of `keytype`.
fn ssh_public(key: &Key, keytype: SshKeyType) -> Result<SshPublic, SignatureFault> {
    let (line_type, encoded) = key.keyval.public.split_once(' ').ok_or(SignatureFault::Key)?;
    if key.keytype != keytype.name() || line_type != keytype.name() {
        return Err(SignatureFault::Key);
    }
    let wire = Base64::decode_vec(encoded).map_err(|_| SignatureFault::Key)?;
    if Base64::encode_string(&wire) != encoded {
        return Err(SignatureFault::Key);
    }
    let material = key_material(&wire, keytype).ok_or(SignatureFault::Key)?;
    Ok(SshPublic { wire, material })
}

fn key_material(wire: &[u8], keytype: SshKeyType) -> Option<Material> {
    let mut reader = Wire::new(wire);
    if reader.string()? != keytype.name().as_bytes() {
        return None;
    }
    let p256_point = |reader: &mut Wire<'_>| {
        (reader.string()? == b"nistp256").then_some(())?;
        P256VerifyingKey::from_sec1_bytes(reader.string()?).ok()
    };
    let material = match keytype {
        SshKeyType::Ed25519 => Material::Ed25519(reader.string()?.try_into().ok()?),
        SshKeyType::EcdsaP256 => Material::EcdsaP256(p256_point(&mut reader)?),
        SshKeyType::SkEd25519 => {
            let key = reader.string()?.try_into().ok()?;
            Material::SkEd25519 { key, application: reader.string()?.to_vec() }
        }
        SshKeyType::SkEcdsaP256 => {
            let key = p256_point(&mut reader)?;
            Material::SkEcdsaP256 { key, application: reader.string()?.to_vec() }
        }
    };
    reader.finish()?;
    Some(material)
}
```

The key ring compares keys, not their spellings (§4). An Ed25519 key in
TUF's hex form and the same key as an SSH line are one key, so each listed
key is reduced to its SSH wire encoding where it decodes. A key that
decodes in neither form is compared by its key type and text.

<a name="chunk-ssh-keys-2"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#ssh-keys` · continues</sub>

```rust {#ssh-keys}

/// The public key a key object holds, whatever form the object writes it in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PublicIdentity {
    Decoded(Vec<u8>),
    Undecoded { keytype: String, public: String },
}

pub(crate) fn public_identity(key: &Key) -> PublicIdentity {
    let wire = match key.keytype.as_str() {
        "ed25519" => ed25519_public(key).ok().map(|public| {
            let mut wire = Vec::new();
            put_string(&mut wire, b"ssh-ed25519");
            put_string(&mut wire, &public);
            wire
        }),
        _ => key.keyval.public.split_once(' ').and_then(|(_, encoded)| Base64::decode_vec(encoded).ok()),
    };
    wire.map(PublicIdentity::Decoded).unwrap_or_else(|| PublicIdentity::Undecoded {
        keytype: key.keytype.clone(),
        public: key.keyval.public.clone(),
    })
}
```

An SSHSIG envelope holds the signer's public key, the namespace, a
reserved string, the hash algorithm and the signature. The signer does not
sign the message itself. It signs a blob that holds the preamble
`SSHSIG`, the namespace, the reserved string, the hash algorithm and the
message's hash, so a signature under one namespace never verifies under
another. The check refuses trailing bytes, names a wrong namespace as
such, so a git commit signature made by a maintainer's key is reported for
what it is, and requires the envelope's key to be the listed key.

<a name="chunk-check-sshsig"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#check-sshsig`</sub>

```rust {#check-sshsig}

/// An SSHSIG envelope, as its binary form holds it.
pub(crate) struct Envelope<'a> {
    pub(crate) public_key: &'a [u8],
    namespace: &'a [u8],
    hash_algorithm: &'a [u8],
    signature: &'a [u8],
}

pub(crate) fn parse_sshsig(blob: &[u8]) -> Option<Envelope<'_>> {
    let mut reader = Wire::new(blob);
    (reader.bytes(6)? == b"SSHSIG" && reader.u32()? == 1).then_some(())?;
    let public_key = reader.string()?;
    let namespace = reader.string()?;
    reader.string()?;
    let hash_algorithm = reader.string()?;
    let signature = reader.string()?;
    reader.finish()?;
    Some(Envelope { public_key, namespace, hash_algorithm, signature })
}

/// The blob an SSHSIG signer signs for `message`.
fn sshsig_signed_data(namespace: &[u8], hash_algorithm: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let digest = match hash_algorithm {
        b"sha512" => Sha512::digest(message).to_vec(),
        b"sha256" => Sha256::digest(message).to_vec(),
        _ => return None,
    };
    let mut signed = b"SSHSIG".to_vec();
    put_string(&mut signed, namespace);
    put_string(&mut signed, b"");
    put_string(&mut signed, hash_algorithm);
    put_string(&mut signed, &digest);
    Some(signed)
}

fn check_sshsig(key: &Key, keytype: SshKeyType, message: &[u8], sig_hex: &str) -> Result<Option<u8>, SignatureFault> {
    let public = ssh_public(key, keytype)?;
    let blob = hex::decode(sig_hex).map_err(|_| SignatureFault::Encoding)?;
    let envelope = parse_sshsig(&blob).ok_or(SignatureFault::Encoding)?;
    if envelope.namespace != NAMESPACE.as_bytes() {
        return Err(SignatureFault::Namespace(String::from_utf8_lossy(envelope.namespace).into_owned()));
    }
    if envelope.public_key != public.wire.as_slice() {
        return Err(SignatureFault::Invalid);
    }
    let signed = sshsig_signed_data(envelope.namespace, envelope.hash_algorithm, message)
        .ok_or(SignatureFault::Encoding)?;
    check_signature_blob(&public.material, &signed, envelope.signature)
}
```

The signature inside the envelope names its algorithm, then holds the
signature: 64 bytes for Ed25519, two integers `r` and `s` for ECDSA. A
plain key signs the SSHSIG blob directly, Ed25519 as is and ECDSA over its
SHA-256. A FIDO2 token cannot sign arbitrary bytes. Per OpenSSH
`PROTOCOL.u2f`, it signs the SHA-256 of the key's application, a flags
byte, a 32-bit counter and the SHA-256 of the blob, and the signature
carries the flags and the counter after it. Flag `0x01` says a person
touched the token, `0x04` that the token verified them. The check returns
the flags, and the signatory's rule reads them (below).

A passkey signs through WebAuthn, so the browser wraps the challenge in a
block of client data, and the authenticator signs its authenticator data
and the client data's hash. OpenSSH carries this as the
`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature of an `sk-ecdsa`
key, with the origin, the client data and the extensions after the flags
and counter. The check follows OpenSSH's own (`ssh-ecdsa-sk.c`): the
client data must begin with the type `webauthn.get`, the blob as its
challenge in unpadded base64url, and the origin, in that order, and the
origin may not hold a quote; the flags may not claim attested data, and
the extension flag must match whether extensions are present. The
authenticator data is rebuilt from the application's hash, the flags, the
counter and the extensions, so the relying party a passkey signs for is
the key's application.

<a name="chunk-sk-signatures"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#sk-signatures`</sub>

```rust {#sk-signatures}
fn check_signature_blob(material: &Material, signed: &[u8], blob: &[u8]) -> Result<Option<u8>, SignatureFault> {
    let encoding = SignatureFault::Encoding;
    let mut reader = Wire::new(blob);
    let algorithm = reader.string().ok_or(encoding.clone())?;
    let signature = reader.string().ok_or(encoding.clone())?;
    let trailer = |reader: &mut Wire<'_>| Some((reader.u8()?, reader.u32()?));
    match (material, algorithm) {
        (Material::Ed25519(key), b"ssh-ed25519") => {
            reader.finish().ok_or(encoding)?;
            verify_ed25519(key, signed, signature).map(|()| None)
        }
        (Material::EcdsaP256(key), b"ecdsa-sha2-nistp256") => {
            reader.finish().ok_or(encoding)?;
            verify_p256(key, signed, signature).map(|()| None)
        }
        (Material::SkEd25519 { key, application }, b"sk-ssh-ed25519@openssh.com") => {
            let (flags, counter) = trailer(&mut reader).ok_or(encoding.clone())?;
            reader.finish().ok_or(encoding)?;
            let data = sk_signed_data(application, flags, counter, b"", &Sha256::digest(signed));
            verify_ed25519(key, &data, signature).map(|()| Some(flags))
        }
        (Material::SkEcdsaP256 { key, application }, b"sk-ecdsa-sha2-nistp256@openssh.com") => {
            let (flags, counter) = trailer(&mut reader).ok_or(encoding.clone())?;
            reader.finish().ok_or(encoding)?;
            let data = sk_signed_data(application, flags, counter, b"", &Sha256::digest(signed));
            verify_p256(key, &data, signature).map(|()| Some(flags))
        }
        (Material::SkEcdsaP256 { key, application }, b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com") => {
            let (flags, counter) = trailer(&mut reader).ok_or(encoding.clone())?;
            let origin = reader.string().ok_or(encoding.clone())?;
            let client_data = reader.string().ok_or(encoding.clone())?;
            let extensions = reader.string().ok_or(encoding.clone())?;
            reader.finish().ok_or(encoding)?;
            let client_hash = webauthn_client_hash(signed, origin, client_data, flags, extensions)?;
            let data = sk_signed_data(application, flags, counter, extensions, &client_hash);
            verify_p256(key, &data, signature).map(|()| Some(flags))
        }
        _ => Err(encoding),
    }
}

/// What a FIDO2 token or a WebAuthn authenticator signs (OpenSSH PROTOCOL.u2f).
fn sk_signed_data(application: &[u8], flags: u8, counter: u32, extensions: &[u8], message_hash: &[u8]) -> Vec<u8> {
    let mut data = Sha256::digest(application).to_vec();
    data.push(flags);
    data.extend(counter.to_be_bytes());
    data.extend(extensions);
    data.extend(message_hash);
    data
}

/// Checks the WebAuthn client data against the blob it must carry, and hashes it.
fn webauthn_client_hash(
    challenge: &[u8],
    origin: &[u8],
    client_data: &[u8],
    flags: u8,
    extensions: &[u8],
) -> Result<Vec<u8>, SignatureFault> {
    let attested = flags & 0x40 != 0;
    let extended = flags & 0x80 != 0;
    if origin.contains(&b'"') || attested || extended == extensions.is_empty() {
        return Err(SignatureFault::Encoding);
    }
    let mut expected = br#"{"type":"webauthn.get","challenge":""#.to_vec();
    expected.extend(Base64UrlUnpadded::encode_string(challenge).as_bytes());
    expected.extend(br#"","origin":""#);
    expected.extend(origin);
    expected.push(b'"');
    if !client_data.starts_with(&expected) {
        return Err(SignatureFault::ClientData);
    }
    Ok(Sha256::digest(client_data).to_vec())
}

/// Verifies an OpenSSH ECDSA signature, two `mpint`s, over the SHA-256 of `data`.
fn verify_p256(key: &P256VerifyingKey, data: &[u8], signature: &[u8]) -> Result<(), SignatureFault> {
    let mut reader = Wire::new(signature);
    let r = reader.string().and_then(scalar_bytes).ok_or(SignatureFault::Encoding)?;
    let s = reader.string().and_then(scalar_bytes).ok_or(SignatureFault::Encoding)?;
    reader.finish().ok_or(SignatureFault::Encoding)?;
    let signature = P256Signature::from_scalars(r, s).map_err(|_| SignatureFault::Encoding)?;
    key.verify(data, &signature).map_err(|_| SignatureFault::Invalid)
}

/// A positive `mpint` as a 32-byte big-endian scalar.
fn scalar_bytes(mpint: &[u8]) -> Option<p256::FieldBytes> {
    if mpint.first().is_some_and(|byte| byte & 0x80 != 0) {
        return None;
    }
    let start = mpint.iter().position(|byte| *byte != 0).unwrap_or(mpint.len());
    let digits = &mpint[start..];
    let mut scalar = [0u8; 32];
    scalar.get_mut(32usize.checked_sub(digits.len())?..)?.copy_from_slice(digits);
    Some(scalar.into())
}
```

## Counting signatories

TUF counts distinct keys toward a threshold. Alice holds two keys, so under
TUF's count she alone meets a threshold of two. §4 counts signatories
instead. The counting has three steps:

1. Each signature whose key id the role lists is checked once. A repeated
   key id counts once, as TUF requires.
2. A signatory counts when at least their rule's number of their keys
   verified, each signature carrying the flags their rule demands. A rule
   can demand `user-present`, that a person touched the token, and
   `user-verified`, that the token checked their PIN or biometric. A
   signature that verifies but lacks a flag does not count, and its
   verdict names the missing flag.
3. The role is met when the number of signatories that count reaches its
   threshold.

First, the key listing. A ring checks every listed id against the id its
key hashes to, and refuses two ids for one public key, in whatever form
each writes it.

<a name="chunk-quorum"></a><sub>[`src/quorum.rs`](../../crates/x0k-release-metadata/src/quorum.rs) · `#quorum` · assembles [quorum-rule](#chunk-quorum-rule) · [tally](#chunk-tally)</sub>

```rust {#quorum file="src/quorum.rs"}
use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::Signature;
use crate::scheme::{public_identity, PublicIdentity};
use crate::{
    scheme, Key, ListedKey, Malformed, Refusal, Rule, SignatoryRule, SignatoryVerdict, SignatureFault,
};

/// A checked key listing: key ids that match their keys, one id per public key.
pub(crate) struct KeyRing<'a> {
    keys: BTreeMap<&'a str, &'a Key>,
}

impl<'a> KeyRing<'a> {
    pub(crate) fn new(listing: &'a BTreeMap<String, ListedKey>) -> Result<Self, Malformed> {
        let mut by_public: BTreeMap<PublicIdentity, &str> = BTreeMap::new();
        for (id, listed) in listing {
            if *id != listed.computed_id {
                return Err(Malformed::KeyId { listed: id.clone() });
            }
            if let Some(first) = by_public.insert(public_identity(&listed.key), id) {
                return Err(Malformed::DuplicateKey {
                    first: first.to_owned(),
                    second: id.clone(),
                });
            }
        }
        let keys = listing.iter().map(|(id, l)| (id.as_str(), &l.key)).collect();
        Ok(Self { keys })
    }
}

fn signatory_of(keyid: &str, key: &Key) -> String {
    key.signatory.clone().unwrap_or_else(|| keyid.to_owned())
}

/// Refuses a presence rule for a signatory who holds a key whose
/// signatures carry no flags (decision §4).
pub(crate) fn presence_rules_hold<'k>(
    keys: impl IntoIterator<Item = (&'k str, &'k Key)>,
    rules: &BTreeMap<String, SignatoryRule>,
) -> Result<(), Malformed> {
    for (keyid, key) in keys {
        let signatory = signatory_of(keyid, key);
        let demands = rules.get(&signatory).is_some_and(|rule| !rule.flags.is_empty());
        if demands && !scheme::proves_presence(key) {
            return Err(Malformed::PresenceWithoutFlags { signatory, keyid: keyid.to_owned() });
        }
    }
    Ok(())
}

<<quorum-rule>>

<<tally>>
```

A quorum is one role's rule, checked when it is built: every key id the
role lists is in the ring, the threshold is at least one, no signatory
requires zero keys, and no signatory whose rule demands presence flags
holds a key of the role whose signatures cannot carry them.

<a name="chunk-quorum-rule"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#quorum-rule`</sub>

```rust {#quorum-rule}
/// One role's signing rule.
pub(crate) struct Quorum<'a> {
    role: &'a str,
    keyids: &'a [String],
    threshold: u64,
    ring: &'a KeyRing<'a>,
    rules: &'a BTreeMap<String, SignatoryRule>,
}

impl<'a> Quorum<'a> {
    pub(crate) fn new(
        role: &'a str,
        keyids: &'a [String],
        threshold: u64,
        ring: &'a KeyRing<'a>,
        rules: &'a BTreeMap<String, SignatoryRule>,
    ) -> Result<Self, Malformed> {
        if threshold == 0 {
            return Err(Malformed::ZeroThreshold { role: role.to_owned() });
        }
        if let Some(keyid) = keyids.iter().find(|id| !ring.keys.contains_key(id.as_str())) {
            return Err(Malformed::UnknownKeyId {
                role: role.to_owned(),
                keyid: keyid.clone(),
            });
        }
        if let Some((signatory, _)) = rules.iter().find(|(_, rule)| rule.keys_required == 0) {
            return Err(Malformed::ZeroKeysRequired { signatory: signatory.clone() });
        }
        let keys = keyids.iter().filter_map(|id| ring.keys.get(id.as_str()).map(|key| (id.as_str(), *key)));
        presence_rules_hold(keys, rules)?;
        Ok(Self { role, keyids, threshold, ring, rules })
    }
}
```

The tally runs the three steps. A verdict exists for every signatory the
role lists, so a refusal names who signed and did not count, and who did
not sign at all. The verifier requires the tally to meet the threshold;
the ceremony's status command shows the same tally while it does not.

<a name="chunk-tally"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#tally`</sub>

```rust {#tally}
/// How a role's signatures stand: how many signatories count, and each one's verdict.
pub(crate) struct Tally {
    pub counted: u64,
    pub verdicts: Vec<SignatoryVerdict>,
    pub unlisted_keys: Vec<String>,
}

impl Quorum<'_> {
    /// Refuses unless enough signatories count; `rule` words the failure.
    pub(crate) fn require(
        &self,
        message: &[u8],
        signatures: &[Signature],
        rule: impl FnOnce(u64, u64) -> Rule,
    ) -> Result<(), Refusal> {
        let tally = self.tally(message, signatures);
        if tally.counted >= self.threshold {
            return Ok(());
        }
        let counted = tally.counted;
        tracing::debug!(role = self.role, counted, threshold = self.threshold, "release_metadata.quorum.unmet");
        Err(Refusal {
            role: self.role.to_owned(),
            rule: rule(self.threshold, counted),
            signatories: tally.verdicts,
            unlisted_keys: tally.unlisted_keys,
        })
    }

    /// Refuses unless every signatory the role lists counts (decision §8).
    pub(crate) fn require_every(&self, message: &[u8], signatures: &[Signature]) -> Result<(), Refusal> {
        let tally = self.tally(message, signatures);
        let signatories = self.signatory_count();
        if tally.counted >= signatories {
            return Ok(());
        }
        Err(Refusal {
            role: self.role.to_owned(),
            rule: Rule::PublicDelegation { signatories, counted: tally.counted },
            signatories: tally.verdicts,
            unlisted_keys: tally.unlisted_keys,
        })
    }

    /// How many distinct signatories the role's keys belong to.
    pub(crate) fn signatory_count(&self) -> u64 {
        let named: BTreeSet<String> = self
            .keyids
            .iter()
            .filter_map(|keyid| self.ring.keys.get(keyid.as_str()).map(|key| signatory_of(keyid, key)))
            .collect();
        named.len() as u64
    }

    /// Counts the signatories whose signatures over `message` verify.
    pub(crate) fn tally(&self, message: &[u8], signatures: &[Signature]) -> Tally {
        let mut verdicts: BTreeMap<String, SignatoryVerdict> = BTreeMap::new();
        for keyid in self.keyids {
            if let Some(key) = self.ring.keys.get(keyid.as_str()) {
                let signatory = signatory_of(keyid, key);
                let required_keys = self.rules.get(&signatory).map_or(1, |r| r.keys_required);
                verdicts.entry(signatory.clone()).or_insert(SignatoryVerdict {
                    signatory,
                    valid_keys: 0,
                    required_keys,
                    counted: false,
                    faults: Vec::new(),
                });
            }
        }
        let mut seen = BTreeSet::new();
        let mut unlisted_keys = Vec::new();
        for signature in signatures {
            if !seen.insert(signature.keyid.as_str()) {
                continue;
            }
            let listed = self.keyids.contains(&signature.keyid);
            let key = match self.ring.keys.get(signature.keyid.as_str()) {
                Some(key) if listed => *key,
                _ => {
                    unlisted_keys.push(signature.keyid.clone());
                    continue;
                }
            };
            let Some(verdict) = verdicts.get_mut(&signatory_of(&signature.keyid, key)) else {
                continue;
            };
            let required = self.rules.get(&verdict.signatory).map_or(&[][..], |rule| rule.flags.as_slice());
            match scheme::check_signature(key, message, &signature.sig) {
                Ok(flags) => match required.iter().find(|flag| flags.is_none_or(|bits| bits & flag.bit() == 0)) {
                    Some(missing) => verdict.faults.push((signature.keyid.clone(), SignatureFault::MissingFlag(missing.name()))),
                    None => verdict.valid_keys += 1,
                },
                Err(fault) => verdict.faults.push((signature.keyid.clone(), fault)),
            }
        }
        let mut counted = 0;
        for verdict in verdicts.values_mut() {
            verdict.counted = verdict.valid_keys >= verdict.required_keys;
            counted += u64::from(verdict.counted);
        }
        Tally { counted, verdicts: verdicts.into_values().collect(), unlisted_keys }
    }
}
```

## The client workflow

`verify` is TUF's § "Detailed client workflow" with the fetching taken out.
The time is fixed once, by the caller. Then the root, the timestamp, the
snapshot and the targets are each updated in turn, and the target is looked
up and matched against the artifact.

<a name="chunk-verify"></a><sub>[`src/verify.rs`](../../crates/x0k-release-metadata/src/verify.rs) · `#verify` · assembles [state](#chunk-state) · [update-root](#chunk-update-root) · [update-timestamp](#chunk-update-timestamp) · [update-snapshot](#chunk-update-snapshot) · [find-target](#chunk-find-target) · [checks](#chunk-checks)</sub>

```rust {#verify file="src/verify.rs"}
use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use sha2::{Digest, Sha256, Sha512};

use crate::canonical::{open_envelope, Envelope};
use crate::metadata::Typed;
use crate::quorum::{presence_rules_hold, KeyRing, Quorum};
use crate::{
    parse_utc, Malformed, MetaFile, Refusal, Root, Rule, Snapshot, TargetEntry, Targets,
    Timestamp,
};

<<state>>

/// Verifies `path` against the fetched metadata, from the trusted state, at `now`.
pub fn verify(
    trusted: &TrustedState,
    fetched: &Fetched,
    path: &str,
    artifact: &Artifact,
    now: SystemTime,
) -> Result<Verified, Refusal> {
    let (root, root_bytes, keep_online) = update_root(trusted, fetched, now)?;
    let trusted_online = |bytes: &Option<Vec<u8>>| bytes.clone().filter(|_| keep_online);
    let timestamp = update_timestamp(&root, trusted_online(&trusted.timestamp), fetched, now)?;
    let snapshot = update_snapshot(&root, &timestamp, trusted_online(&trusted.snapshot), fetched, now)?;
    let mut loaded = BTreeMap::new();
    let (role, entry) = find_target(&root, &snapshot, fetched, path, now, &mut loaded)?;
    check_artifact(&role, &entry, artifact)?;
    Ok(Verified {
        target: VerifiedTarget { path: path.to_owned(), role, entry },
        trusted: TrustedState {
            root: root_bytes.to_vec(),
            timestamp: Some(fetched.timestamp.clone()),
            snapshot: Some(fetched.snapshot.clone()),
            targets: loaded,
        },
    })
}

<<update-root>>

<<update-timestamp>>

<<update-snapshot>>

<<find-target>>

<<checks>>
```

The trusted state is the bytes of the files the reader last verified, so
the embedder stores it as files and passes it back unchanged. The fetched
metadata is bytes too: the newer roots in version order, the timestamp, the
snapshot, and each targets file by role name. The embedder fetches the
delegated roles a lookup can reach; one that is missing is refused as
`missing`.

<a name="chunk-state"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#state`</sub>

```rust {#state}
/// What a reader trusts between updates: the bytes of its last verified metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedState {
    pub root: Vec<u8>,
    pub timestamp: Option<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
    pub targets: BTreeMap<String, Vec<u8>>,
}

impl TrustedState {
    /// The state of a reader that trusts only the root it shipped with.
    pub fn from_root(root: Vec<u8>) -> Self {
        Self { root, timestamp: None, snapshot: None, targets: BTreeMap::new() }
    }
}

/// The metadata an embedder fetched for one update.
#[derive(Debug, Clone, Default)]
pub struct Fetched {
    /// Root versions N+1, N+2, … after the trusted root N, in order.
    pub roots: Vec<Vec<u8>>,
    pub timestamp: Vec<u8>,
    pub snapshot: Vec<u8>,
    /// Targets files by role name: `targets` and each delegated role.
    pub targets: BTreeMap<String, Vec<u8>>,
}

/// The length and hashes the embedder computed over the downloaded artifact.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub length: u64,
    pub hashes: BTreeMap<String, String>,
}

/// A target that verified, and the role that listed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTarget {
    pub path: String,
    pub role: String,
    pub entry: TargetEntry,
}

/// The outcome of a successful update.
#[derive(Debug, Clone)]
pub struct Verified {
    pub target: VerifiedTarget,
    pub trusted: TrustedState,
}
```

### The root walk

Decision §5 is TUF's § "Update the root role". Root version N+1 counts only
when it carries the threshold of version N's root role and the threshold of
its own, each counted by signatory under that version's rules. The reader
walks every version from its trusted root, one at a time, and each version
must be exactly one more than the last. After the walk the newest root must
not be expired. If the walk changed the keys of the timestamp or snapshot
role, the reader drops its trusted timestamp and snapshot (step 11), so a
compromised online key cannot pin a version far in the future.

Each root's key listing is checked as the root is opened, the trusted one
included. So a root that lists one public key under two key ids is refused
as `root` before any release is read (§4), and not later, under the first
role whose signatures happen to be counted. So is a root whose presence
rule names a signatory who holds a key that is not an `sk` key, whose
signatures can never carry the flags.

<a name="chunk-update-root"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#update-root`</sub>

```rust {#update-root}
fn update_root<'f>(
    trusted: &'f TrustedState,
    fetched: &'f Fetched,
    now: SystemTime,
) -> Result<(Root, &'f [u8], bool), Refusal> {
    let open = |bytes: &[u8]| {
        let root: Envelope<Root> = open_envelope(bytes).map_err(|e| Refusal::new("root", e))?;
        KeyRing::new(&root.body.keys).map_err(|e| Refusal::new("root", e))?;
        let keys = root.body.keys.iter().map(|(id, listed)| (id.as_str(), &listed.key));
        presence_rules_hold(keys, &root.body.signatories).map_err(|e| Refusal::new("root", e))?;
        Ok::<_, Refusal>(root)
    };
    let first = open(&trusted.root)?;
    let mut current = first.body.clone();
    let mut current_bytes = trusted.root.as_slice();
    for bytes in &fetched.roots {
        let next = open(bytes)?;
        for keys_of in [&current, &next.body] {
            let version = keys_of.version;
            role_quorum(keys_of, "root", |quorum| {
                quorum.require(&next.canonical, &next.signatures, |threshold, counted| {
                    Rule::RootThreshold { keys_of: version, threshold, counted }
                })
            })?;
        }
        if current.version.checked_add(1) != Some(next.body.version) {
            return Err(Refusal::new(
                "root",
                Rule::RootSequence { trusted: current.version, offered: next.body.version },
            ));
        }
        current = next.body;
        current_bytes = bytes;
    }
    check_expiry("root", &current, now)?;
    let unchanged = |role: &str| {
        let keys = |root: &Root| root.roles.get(role).map(|r| r.keyids.iter().cloned().collect::<BTreeSet<_>>());
        keys(&first.body) == keys(&current)
    };
    let keep_online = unchanged("timestamp") && unchanged("snapshot");
    Ok((current, current_bytes, keep_online))
}

/// Runs `check` with the quorum of a top-level role that `root` lists.
fn role_quorum<T>(
    root: &Root,
    role: &str,
    check: impl FnOnce(&Quorum<'_>) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    let malformed = |e: Malformed| Refusal::new(role, e);
    let keys = root
        .roles
        .get(role)
        .ok_or_else(|| malformed(Malformed::MissingRole { role: role.to_owned() }))?;
    let ring = KeyRing::new(&root.keys).map_err(malformed)?;
    let quorum = Quorum::new(role, &keys.keyids, keys.threshold, &ring, &root.signatories)
        .map_err(malformed)?;
    check(&quorum)
}
```

### Timestamp and snapshot

The timestamp must meet its role's threshold, must not be lower than the
trusted timestamp, must not list a lower snapshot version than the trusted
one did, and must not be expired (§ "Update the timestamp role"). An equal
version is accepted: TUF stops the update there because nothing changed,
and continuing with an unchanged timestamp reaches the same answer.

<a name="chunk-update-timestamp"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#update-timestamp`</sub>

```rust {#update-timestamp}
fn update_timestamp(
    root: &Root,
    trusted: Option<Vec<u8>>,
    fetched: &Fetched,
    now: SystemTime,
) -> Result<Timestamp, Refusal> {
    let role = "timestamp";
    let new: Envelope<Timestamp> = open_envelope(&fetched.timestamp).map_err(|e| Refusal::new(role, e))?;
    role_quorum(root, role, |q| q.require(&new.canonical, &new.signatures, threshold))?;
    if let Some(bytes) = trusted {
        let old: Envelope<Timestamp> = open_envelope(&bytes).map_err(|e| Refusal::new(role, e))?;
        check_not_lower(role, old.body.version, new.body.version)?;
        if let Some(old_snapshot) = old.body.meta.get("snapshot.json") {
            let offered = snapshot_listing(&new.body)?.version;
            check_not_lower("snapshot", old_snapshot.version, offered)?;
        }
    }
    check_expiry(role, &new.body, now)?;
    Ok(new.body)
}

fn snapshot_listing(timestamp: &Timestamp) -> Result<&MetaFile, Refusal> {
    timestamp
        .meta
        .get("snapshot.json")
        .ok_or_else(|| Refusal::new("snapshot", Rule::Unlisted { lister: "timestamp".to_owned() }))
}

fn threshold(threshold: u64, counted: u64) -> Rule {
    Rule::Threshold { threshold, counted }
}
```

The snapshot must match the length and hashes the timestamp lists, meet its
threshold, carry the version the timestamp lists, keep listing every file
the trusted snapshot listed at no lower version, and not be expired (§
"Update the snapshot role"). The last-but-one check is what stops a
rollback of any targets file.

<a name="chunk-update-snapshot"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#update-snapshot`</sub>

```rust {#update-snapshot}
fn update_snapshot(
    root: &Root,
    timestamp: &Timestamp,
    trusted: Option<Vec<u8>>,
    fetched: &Fetched,
    now: SystemTime,
) -> Result<Snapshot, Refusal> {
    let role = "snapshot";
    let listed = snapshot_listing(timestamp)?;
    check_listing(role, "timestamp", listed, &fetched.snapshot)?;
    let new: Envelope<Snapshot> = open_envelope(&fetched.snapshot).map_err(|e| Refusal::new(role, e))?;
    role_quorum(root, role, |q| q.require(&new.canonical, &new.signatures, threshold))?;
    check_listed_version(role, "timestamp", listed, new.body.version)?;
    if let Some(bytes) = trusted {
        let old: Envelope<Snapshot> = open_envelope(&bytes).map_err(|e| Refusal::new(role, e))?;
        for (file, old_meta) in &old.body.meta {
            let Some(new_meta) = new.body.meta.get(file) else {
                return Err(Refusal::new(role, Rule::SnapshotDropsRole { file: file.clone() }));
            };
            let file_role = file.strip_suffix(".json").unwrap_or(file);
            check_not_lower(file_role, old_meta.version, new_meta.version)?;
        }
    }
    check_expiry(role, &new.body, now)?;
    Ok(new.body)
}
```

### Targets and audiences

A targets file, top-level or delegated, is loaded the same way: the
snapshot must list it, its bytes must match the listing, it must meet the
threshold its delegator sets, carry the listed version and not be expired
(§ "Update the targets role").

One rule is the decision's own (§8). Signatories can approve a release
before it is built: they sign a version of their audience's targets file
that delegates one version's files, such as `fleet/chariot-1.1-*`, to a key
a session made, and that version expires within a day; the ceremony's
`stage` command refuses one that expires later
(`implementation:release-metadata/ceremony`), since the metadata records
no start the verifier could hold it to. The session then signs the
artifact's entry with its key. The walk below already confines
the session's role to the delegated pattern, and the delegating file's
expiry ends the grant. For an audience the root marks public, the file
that delegates must also carry every signatory its role lists, not only
its threshold, since the signatories do not see the final change. A
public file that delegates nothing, an ordinary release, needs only its
threshold.

<a name="chunk-find-target"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#find-target`</sub>

```rust {#find-target}
fn load_targets(
    role: &str,
    quorum: &Quorum<'_>,
    public: bool,
    snapshot: &Snapshot,
    fetched: &Fetched,
    now: SystemTime,
    loaded: &mut BTreeMap<String, Vec<u8>>,
) -> Result<Targets, Refusal> {
    let listed = snapshot
        .meta
        .get(&format!("{role}.json"))
        .ok_or_else(|| Refusal::new(role, Rule::Unlisted { lister: "snapshot".to_owned() }))?;
    let bytes = fetched
        .targets
        .get(role)
        .ok_or_else(|| Refusal::new(role, Rule::Missing))?;
    check_listing(role, "snapshot", listed, bytes)?;
    let envelope: Envelope<Targets> = open_envelope(bytes).map_err(|e| Refusal::new(role, e))?;
    quorum.require(&envelope.canonical, &envelope.signatures, threshold)?;
    if public && envelope.body.delegates() {
        quorum.require_every(&envelope.canonical, &envelope.signatures)?;
    }
    check_listed_version(role, "snapshot", listed, envelope.body.version)?;
    check_expiry(role, &envelope.body, now)?;
    loaded.insert(role.to_owned(), bytes.clone());
    Ok(envelope.body)
}
```

The lookup is TUF's pre-order depth-first search over the delegations. It
walks into a delegation only when that delegation covers the path, so every
role on the chain covers it, as TUF requires. This is what makes an
audience a boundary (decision §2). A reader enrolled for `pilot` looks up
`pilot/chariot-1.0.tar`, and only the `pilot` delegation covers that path.
The `fleet` role is never read, so an entry for that path inside `fleet`
cannot verify, whoever signed it.

Before the search, the path must have the flat form of §2: an audience's
name, one `/`, and a file name, neither empty. A deeper path, such as
`fleet/chariot/chariot-1.0.tar`, is refused as an unknown target even when
a delegation's patterns cover it and a role lists it. The form is the
format's, so it does not rest on each root writing its patterns right.

TUF ends the search and reports the target as not found when a delegated
role fails to load. This verifier returns that role's refusal instead, so a
threshold that Alice's two keys did not meet is reported as a threshold and
not as an unknown target. A terminating delegation that does not list the
target ends the search.

<a name="chunk-find-target-2"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#find-target` · continues</sub>

```rust {#find-target}

const TOP_LEVEL: [&str; 4] = ["root", "targets", "snapshot", "timestamp"];
const MAX_DELEGATIONS: usize = 32;

fn find_target(
    root: &Root,
    snapshot: &Snapshot,
    fetched: &Fetched,
    path: &str,
    now: SystemTime,
    loaded: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(String, TargetEntry), Refusal> {
    let unknown = || Refusal::new("targets", Rule::UnknownTarget { path: path.to_owned() });
    if !is_flat_target_path(path) {
        return Err(unknown());
    }
    let public = root.public_audiences.contains("targets");
    let top = role_quorum(root, "targets", |q| load_targets("targets", q, public, snapshot, fetched, now, loaded))?;
    let mut search = Search { root, snapshot, fetched, path, now, visited: BTreeSet::new() };
    search.walk("targets", &top, loaded)?.ok_or_else(unknown)
}

/// Whether `path` is an audience's name, one `/` and a file name (decision §2).
fn is_flat_target_path(path: &str) -> bool {
    matches!(
        path.split_once('/'),
        Some((audience, file)) if !audience.is_empty() && !file.is_empty() && !file.contains('/')
    )
}

struct Search<'a> {
    root: &'a Root,
    snapshot: &'a Snapshot,
    fetched: &'a Fetched,
    path: &'a str,
    now: SystemTime,
    visited: BTreeSet<String>,
}

impl Search<'_> {
    fn walk(
        &mut self,
        role: &str,
        targets: &Targets,
        loaded: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<Option<(String, TargetEntry)>, Refusal> {
        if let Some(entry) = targets.targets.get(self.path) {
            return Ok(Some((role.to_owned(), entry.clone())));
        }
        let Some(delegations) = &targets.delegations else {
            return Ok(None);
        };
        let ring = KeyRing::new(&delegations.keys).map_err(|e| Refusal::new(role, e))?;
        for delegated in &delegations.roles {
            if TOP_LEVEL.contains(&delegated.name.as_str()) {
                return Err(Refusal::new(role, Malformed::ReservedRoleName(delegated.name.clone())));
            }
            if !delegated.covers(self.path) || !self.visited.insert(delegated.name.clone()) {
                continue;
            }
            if self.visited.len() > MAX_DELEGATIONS {
                return Ok(None);
            }
            let name = delegated.name.as_str();
            let quorum = Quorum::new(name, &delegated.keyids, delegated.threshold, &ring, &self.root.signatories)
                .map_err(|e| Refusal::new(name, e))?;
            let public = self.root.public_audiences.contains(name);
            let child = load_targets(name, &quorum, public, self.snapshot, self.fetched, self.now, loaded)?;
            if let Some(found) = self.walk(name, &child, loaded)? {
                return Ok(Some(found));
            }
            if delegated.terminating {
                return Ok(None);
            }
        }
        Ok(None)
    }
}
```

### The checks

The remaining checks are small. A listed length must equal the file's
length, and every listed hash must match; the crate knows `sha256` and
`sha512` and refuses a listing that names another algorithm. The artifact
must have the entry's length, and every hash the embedder supplied in an
algorithm the entry lists must match; at least one must be compared.

<a name="chunk-checks"></a><sub>[`src/lib.rs`](../../crates/x0k-release-metadata/src/lib.rs) · `#checks`</sub>

```rust {#checks}
fn check_expiry<T: Typed>(role: &str, body: &T, now: SystemTime) -> Result<(), Refusal> {
    let expires = parse_utc(body.expires()).map_err(|e| Refusal::new(role, e))?;
    if expires <= now {
        return Err(Refusal::new(role, Rule::Expired { expires: body.expires().to_owned() }));
    }
    Ok(())
}

fn check_not_lower(role: &str, trusted: u64, offered: u64) -> Result<(), Refusal> {
    if offered < trusted {
        return Err(Refusal::new(role, Rule::Rollback { trusted, offered }));
    }
    Ok(())
}

fn check_listed_version(role: &str, lister: &str, listed: &MetaFile, offered: u64) -> Result<(), Refusal> {
    if listed.version != offered {
        let lister = lister.to_owned();
        return Err(Refusal::new(role, Rule::VersionMismatch { lister, listed: listed.version, offered }));
    }
    Ok(())
}

/// The lowercase hex digest of `bytes` under a hash algorithm TUF names.
pub(crate) fn hex_digest(algorithm: &str, bytes: &[u8]) -> Option<String> {
    match algorithm {
        "sha256" => Some(hex::encode(Sha256::digest(bytes))),
        "sha512" => Some(hex::encode(Sha512::digest(bytes))),
        _ => None,
    }
}

fn check_listing(role: &str, lister: &str, listed: &MetaFile, bytes: &[u8]) -> Result<(), Refusal> {
    let offered = bytes.len() as u64;
    if let Some(length) = listed.length.filter(|length| *length != offered) {
        let lister = lister.to_owned();
        return Err(Refusal::new(role, Rule::LengthMismatch { lister, listed: length, offered }));
    }
    for (algorithm, want) in listed.hashes.iter().flatten() {
        let got = hex_digest(algorithm, bytes)
            .ok_or_else(|| Refusal::new(role, Malformed::HashAlgorithm(algorithm.clone())))?;
        if !got.eq_ignore_ascii_case(want) {
            let (lister, algorithm) = (lister.to_owned(), algorithm.clone());
            return Err(Refusal::new(role, Rule::HashMismatch { lister, algorithm }));
        }
    }
    Ok(())
}

fn check_artifact(role: &str, entry: &TargetEntry, artifact: &Artifact) -> Result<(), Refusal> {
    let lister = role.to_owned();
    if entry.length != artifact.length {
        let (listed, offered) = (entry.length, artifact.length);
        return Err(Refusal::new(role, Rule::LengthMismatch { lister, listed, offered }));
    }
    let mut compared = 0;
    for (algorithm, want) in &entry.hashes {
        let known = matches!(algorithm.as_str(), "sha256" | "sha512");
        if let Some(got) = artifact.hashes.get(algorithm).filter(|_| known) {
            if !got.eq_ignore_ascii_case(want) {
                let algorithm = algorithm.clone();
                return Err(Refusal::new(role, Rule::HashMismatch { lister, algorithm }));
            }
            compared += 1;
        }
    }
    if compared == 0 {
        return Err(Refusal::new(role, Rule::NoCommonHash { lister }));
    }
    Ok(())
}
```

## The manifest

The manifest names crates.io dependencies only. The package leaves out
the hardware kit and the interop check, which run from a clone of the
repository, not from the published crate. The dev-dependencies give
the vector generator the signing halves of the two schemes, and the
ceremony tests a scratch directory.

<a name="chunk-manifest"></a><sub>[`Cargo.toml`](../../crates/x0k-release-metadata/Cargo.toml) · `#manifest`</sub>

```toml {#manifest file="Cargo.toml"}
[package]
name = "x0k-release-metadata"
version = "0.2.0"
edition = { workspace = true }
license = "MIT"
description = "Verifies a release against a root of trust its maintainers sign: TUF metadata, thresholds of signatories, and SSHSIG signatures"
repository = "https://github.com/0k-dot-computer/x0k-release-metadata"
keywords = ["tuf", "signing", "release", "fido2", "sshsig"]
categories = ["cryptography", "authentication"]
# The hardware kit and the interop check run from a clone, not from the package.
exclude = ["kit/", "interop/"]
readme = "../../README.md"

[lib]
path = "src/lib.rs"

[dependencies]
ed25519-dalek = { version = "2.2", default-features = false, features = ["std"] }
hex = "0.4"
olpc-cjson = "0.1.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
thiserror = "2"
tracing = "0.1"
base64ct = { version = "1.6", features = ["alloc"] }
p256 = { version = "0.13", default-features = false, features = ["ecdsa", "std"] }

[dev-dependencies]
ed25519-dalek = { version = "2.2", features = ["std"] }
ssh-encoding = { version = "0.2", features = ["alloc"] }
ssh-key = { version = "0.6.7", default-features = false, features = ["std", "alloc", "ed25519"] }
tempfile = "3"
```

## What the tests pin

The conformance vectors are the crate's main test, and their chapter
(`implementation:release-metadata/vectors`) lists the claim each one
proves. This chapter pins the negative space of §7: the sources never name
a clock, a socket, a file, a process or the environment. The check reads
the crate's own sources as text: every module but `signer.rs`, so the
ceremony's own logic is held to the same rule. A dependency could still do I/O behind a
call; the manifest above is the other half of the argument, since none of
its crates fetch or serve anything.

<a name="chunk-purity-tests"></a><sub>[`tests/conformance/purity.rs`](../../crates/x0k-release-metadata/tests/conformance/purity.rs) · `#purity-tests`</sub>

```rust {#purity-tests file="tests/conformance/purity.rs"}
//! Decision §7: the verifier opens no connection and reads no clock.

const SOURCES: [(&str, &str); 9] = [
    ("lib.rs", include_str!("../../src/lib.rs")),
    ("canonical.rs", include_str!("../../src/canonical.rs")),
    ("ceremony.rs", include_str!("../../src/ceremony.rs")),
    ("metadata.rs", include_str!("../../src/metadata.rs")),
    ("quorum.rs", include_str!("../../src/quorum.rs")),
    ("refusal.rs", include_str!("../../src/refusal.rs")),
    ("scheme.rs", include_str!("../../src/scheme.rs")),
    ("time.rs", include_str!("../../src/time.rs")),
    ("verify.rs", include_str!("../../src/verify.rs")),
];

const FORBIDDEN: [&str; 9] = [
    "SystemTime::now",
    "Instant::now",
    "std::net",
    "std::fs",
    "std::process",
    "std::env",
    "File::open",
    "TcpStream",
    "UdpSocket",
];

#[test]
fn the_verifier_reads_no_clock_and_opens_no_connection() {
    for (file, source) in SOURCES {
        for token in FORBIDDEN {
            assert!(!source.contains(token), "src/{file} names {token}");
        }
    }
}
```

What is hard here is not the cryptography but the counting. A key id covers
the whole key object, so the same public key can appear under two ids; the
ring refuses that, or one signature would count for two people. Hardware
schemes add the presence half of a signatory's rule; they and the ceremony
(`implementation:release-metadata/ceremony`) build on the `Quorum` and the
verdicts here.
