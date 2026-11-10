# The signing ceremony of x0k-release-metadata

```turtle folio:document
implementation:release-metadata\/ceremony a x0k:Implementation ;
    x0k:status "draft" ;
    x0k:summary "The stage, sign and status commands of the release-metadata ceremony: a root or targets file is staged once, each signatory signs it on their own machine through a signer program with ssh-keygen's interface, several files at once with one batch signature, the status names who is missing, a targets entry is signed only when it matches the signer's own rebuild, and a release's targets file, snapshot and timestamp take one signature." ;
    x0k:concerns "trust", "delivery", "signing", "keys", "ceremony" ;
    x0k:cites implementation:release-metadata\/release-metadata,
        implementation:release-metadata\/vectors ;
    x0k:implements design:distribution-and-updates ;
    x0k:motivatedBy architecture:release-metadata ;
    folio:tangleCrate "crates/x0k-release-metadata" ;
    folio:tangleRoot "src/ceremony.rs" .
```

The verifier decides whether a reader accepts a root or a release. Someone
must first make those files and collect their signatures. Decision
`x0k:architecture/release-metadata` §5 names the ceremony, which is
tuf-on-ci's signing event without a pull request:

1. One maintainer stages the new file.
2. Each signer adds a signature with their own key, on their own machine.
3. The package shows which signatories are still missing, until every
   threshold is met.

The staged file is an ordinary metadata file with no signatures yet. It
travels between the signers' machines however the publisher keeps its
metadata, for example as a commit on a branch that each signer pulls,
signs and pushes. No signer sees another signer's key, and nothing waits
on a review.

The crate gives the ceremony its commands in one program,
`x0k-release-metadata`: `stage`, `sign` and `status`, and `release`,
`snapshot` and `timestamp` for the files a release adds. The library holds
their logic, so an embedder such as chariot or x0k's own tooling can run
the same steps without the program.

## What the commands must hold

- **Every threshold, counted as the verifier counts** (§5). A staged root
  version N+1 needs the threshold of root version N and its own. A targets
  file needs its role's threshold, from the root or from the targets file
  that delegates it. The status counts each one with the verifier's
  `Quorum`, so the status says "met" exactly when a reader would accept
  those signatures.
- **A signer program, and nothing else, signs** (§7). The commands hold no
  key and choose none. They run the program they are given with
  `ssh-keygen -Y sign`'s arguments, and `ssh-keygen` when given none.
- **One call to the signer per signing, however many files** (§3). Several
  staged files are signed with one batch signature, so a security key is
  touched once; each file shows its own status. A release's targets file,
  its snapshot and its timestamp are one such signing, and so are a root
  and the targets file under it.
- **A rebuild before a release is signed** (§6). Where the build is
  reproducible, `sign` signs a targets file only when every entry matches
  the signer's own rebuild of that artifact, and it names both hashes when
  one does not. Where it is not, the signer says so, and the signature
  approves the release without attesting its build.
- **A grant of at most a day, shown before it is signed** (§8). `stage`
  refuses an audience's targets version that delegates and expires more
  than 24 hours after it is staged; the top-level targets version, which
  delegates the audiences, is not an audience's version and has no such
  bound. The status shows each delegation's patterns and key ids, so the
  signers review exactly what they grant.

<a name="chunk-ceremony"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#ceremony` · assembles [ceremony-error](#chunk-ceremony-error) · [staged-file](#chunk-staged-file) · [requirement](#chunk-requirement) · [standing](#chunk-standing) · [sign](#chunk-sign) · [rebuild](#chunk-rebuild) · [online](#chunk-online) · [release](#chunk-release)</sub>

```rust {#ceremony file="src/ceremony.rs"}
//! The ceremony of decision §5: stage a file, sign it one signatory at a
//! time, and show who is still missing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};

use crate::batch::{self, check_entry};
use crate::canonical::{canonical_json, open_envelope, Covered, Envelope, Signature};
use crate::metadata::Typed;
use crate::quorum::{KeyRing, Quorum};
use crate::scheme::{parse_sshsig, public_identity, PublicIdentity};
use crate::verify::hex_digest;
use crate::time::format_utc;
use crate::{
    parse_utc, DelegatedRole, Key, ListedKey, Malformed, Root, SignatoryRule, SignatoryVerdict,
    SignatureFault, Signer, SignerError, Snapshot, Targets, Timestamp, BATCH_NAMESPACE, NAMESPACE,
};

<<ceremony-error>>

<<staged-file>>

<<requirement>>

<<standing>>

<<sign>>

<<rebuild>>

<<online>>

<<release>>
```

A ceremony step that does not happen says why. The rebuild refusals carry
the path and both values, so a signer can see which artifact differs and
compare the two builds.

<a name="chunk-ceremony-error"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#ceremony-error`</sub>

```rust {#ceremony-error}
/// Why a ceremony step did not happen.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CeremonyError {
    #[error("malformed: {0}")]
    Malformed(#[from] Malformed),
    #[error("people stage root and targets files; sign_snapshot and sign_timestamp make the online roles, not stage: {0}")]
    NotSignedByPeople(String),
    #[error("the staged file is a {found} file, not a {expected} file")]
    WrongKind { expected: &'static str, found: String },
    #[error("staged root version {staged} is not a first root; a first root is version 1")]
    NotFirstVersion { staged: u64 },
    #[error("staged root version {staged} does not follow trusted version {trusted}")]
    NotNextVersion { trusted: u64, staged: u64 },
    #[error("a root is not a delegated role, so it takes no role and no delegating targets file")]
    RootIsNotDelegated,
    #[error("a targets version that delegates is staged with its role: `targets` for the top-level role, or the audience's name")]
    DelegatingRoleUnnamed,
    #[error("this version of {role} delegates and expires at {expires}, more than 24 hours after it is staged")]
    GrantTooLong { role: String, expires: String },
    #[error("the delegating targets file names no role {0}")]
    UnknownRole(String),
    #[error("signer program: {0}")]
    Signer(#[from] SignerError),
    #[error("the signer program did not write an SSH signature")]
    Armor,
    #[error("the signing key is not one that {role}'s thresholds list")]
    KeyNotListed { role: String },
    #[error("there is no staged file to sign")]
    NothingToSign,
    #[error("the {kind} file of role {role} is given twice; one signature covers each file once")]
    RepeatedFile { kind: &'static str, role: String },
    #[error("the new signature does not count: {0}")]
    Signature(#[from] SignatureFault),
    #[error("{path} has no rebuild; rebuild it, or sign as not reproducible")]
    NotRebuilt { path: String },
    #[error("a rebuild names {path}, which no staged targets file lists")]
    RebuiltUnlisted { path: String },
    #[error("the rebuilt {path} is {rebuilt} bytes; the targets entry lists {listed}")]
    RebuildLength { path: String, listed: u64, rebuilt: u64 },
    #[error("the rebuilt {path} has {algorithm} {rebuilt}; the targets entry lists {listed}")]
    RebuildMismatch { path: String, algorithm: String, listed: String, rebuilt: String },
}
```

## Staging

A staged file is the body the maintainer wrote, wrapped with an empty
list of signatures. The ceremony keeps the body as the JSON value it read,
so a field the crate's types do not name survives every signature, as the
verifier requires (`implementation:release-metadata/release-metadata`,
"Canonical JSON"). People sign roots and targets files; the online key
signs the snapshot and the timestamp (§6), so `stage` refuses those.
Staging also opens the result as the verifier would, so a body that does
not parse, or a root whose key listing names one key twice, is refused
before anyone signs it.

A targets version that delegates is staged with the name of its role.
When that role is an audience's, the version grants a session's key the
right to sign one release ahead of its build, and the grant ends when the
version expires (§8). So `stage` refuses such a version that expires more
than 24 hours after the time it is staged, the approver's grant ceiling.
The top-level targets version delegates the audiences themselves, which is
not such a grant, so the role `targets` has no bound. The library takes the
time as an input, as the verifier does; the program reads the clock.

<a name="chunk-staged-file"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#staged-file`</sub>

```rust {#staged-file}
/// A metadata file as the ceremony reads and writes it.
#[derive(Deserialize, Serialize)]
struct StagedFile {
    signed: Value,
    signatures: Vec<Signature>,
}

impl StagedFile {
    fn read(bytes: &[u8]) -> Result<Self, CeremonyError> {
        Ok(serde_json::from_slice(bytes).map_err(Malformed::Json)?)
    }

    fn write(&self) -> Result<Vec<u8>, CeremonyError> {
        let mut out = serde_json::to_vec_pretty(self).map_err(Malformed::Json)?;
        out.push(b'\n');
        Ok(out)
    }
}

/// The kinds of metadata file: people sign roots and targets files; the
/// online key signs snapshots and timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Root,
    Targets,
    Snapshot,
    Timestamp,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Root => "root",
            Kind::Targets => "targets",
            Kind::Snapshot => "snapshot",
            Kind::Timestamp => "timestamp",
        }
    }
}

#[derive(Deserialize)]
struct TypeField {
    #[serde(rename = "_type")]
    kind: String,
}

fn staged_kind(signed: &Value) -> Result<Kind, CeremonyError> {
    let field = TypeField::deserialize(signed).map_err(Malformed::Json)?;
    match field.kind.as_str() {
        "root" => Ok(Kind::Root),
        "targets" => Ok(Kind::Targets),
        "snapshot" => Ok(Kind::Snapshot),
        "timestamp" => Ok(Kind::Timestamp),
        other => Err(Malformed::WrongType { expected: "root or targets", found: other.to_owned() }.into()),
    }
}

/// The longest an audience's delegating version may last after it is staged (§8).
const GRANT_CEILING: Duration = Duration::from_secs(24 * 60 * 60);

/// Stages an unsigned metadata body as a file with no signatures yet (§5,
/// step 1), at `now`. `role` names the role a targets body is a version of:
/// `targets` for the top-level role, or an audience's name; a targets body
/// that delegates must name it.
pub fn stage(body: &[u8], role: Option<&str>, now: SystemTime) -> Result<Vec<u8>, CeremonyError> {
    let signed: Value = serde_json::from_slice(body).map_err(Malformed::Json)?;
    let kind = staged_kind(&signed)?;
    let file = StagedFile { signed, signatures: Vec::new() }.write()?;
    match kind {
        Kind::Root if role.is_some() => return Err(CeremonyError::RootIsNotDelegated),
        Kind::Root => {
            KeyRing::new(&open_envelope::<Root>(&file)?.body.keys)?;
        }
        Kind::Targets => check_grant_end(&open_envelope::<Targets>(&file)?.body, role, now)?,
        online => return Err(CeremonyError::NotSignedByPeople(online.name().to_owned())),
    }
    Ok(file)
}

/// Refuses an audience's delegating version that outlasts the grant ceiling.
fn check_grant_end(targets: &Targets, role: Option<&str>, now: SystemTime) -> Result<(), CeremonyError> {
    if !targets.delegates() {
        return Ok(());
    }
    match role {
        None => Err(CeremonyError::DelegatingRoleUnnamed),
        Some("targets") => Ok(()),
        Some(role) => {
            let expires = parse_utc(&targets.expires)?;
            if now.checked_add(GRANT_CEILING).is_some_and(|ceiling| expires > ceiling) {
                let (role, expires) = (role.to_owned(), targets.expires.clone());
                return Err(CeremonyError::GrantTooLong { role, expires });
            }
            Ok(())
        }
    }
}
```

## Who must sign

A `Requirement` is the list of thresholds a staged file must meet. Each
threshold is one role's rule: its key ids, its count, the key listing the
ids point into, and the signatories' own rules, which always come from
the root. Each kind of staged file has its own constructor, which names
what that kind is checked against, so no constructor takes an argument
that only some kinds use:

- `first_root`: root version 1. Nothing came before it, so its own root
  threshold is the only one (§5), and readers pin it at install (§1).
- `next_root`: root version N+1, checked against version N, the root the
  signer trusts. It needs version N's threshold and its own, and the
  staged version must be exactly one more.
- `targets`: the top-level targets file, under the current root.
- `delegated_targets`: a delegated role's file, under the current root and
  the targets file that delegates it.

Each constructor refuses a staged file of another kind.

A targets file of an audience the root marks public that delegates paths
needs every signatory its role lists (§8), so its threshold is the number
of those signatories, as the verifier counts it.

Each threshold is checked as it is read, with the same `KeyRing` and
`Quorum` the verifier builds, so a ceremony cannot collect signatures
under a rule the verifier would refuse.

<a name="chunk-requirement"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#requirement`</sub>

```rust {#requirement}
/// The thresholds a staged file must meet before a reader accepts it.
pub struct Requirement {
    kind: Kind,
    thresholds: Vec<Threshold>,
}

/// One role's rule, read from the file that delegates the role.
struct Threshold {
    label: String,
    role: String,
    keyids: Vec<String>,
    threshold: u64,
    keys: BTreeMap<String, ListedKey>,
    rules: BTreeMap<String, SignatoryRule>,
}

impl Threshold {
    fn top_level(root: &Root, role: &str, label: String) -> Result<Self, Malformed> {
        let keys = root
            .roles
            .get(role)
            .ok_or_else(|| Malformed::MissingRole { role: role.to_owned() })?;
        Ok(Self {
            label,
            role: role.to_owned(),
            keyids: keys.keyids.clone(),
            threshold: keys.threshold,
            keys: root.keys.clone(),
            rules: root.signatories.clone(),
        })
    }

    fn delegated(root: &Root, delegator: &[u8], role: &str) -> Result<Self, CeremonyError> {
        let unknown = || CeremonyError::UnknownRole(role.to_owned());
        let delegations = open_envelope::<Targets>(delegator)?.body.delegations.ok_or_else(unknown)?;
        let delegated = delegations.roles.iter().find(|r| r.name == role).ok_or_else(unknown)?;
        Ok(Self {
            label: role.to_owned(),
            role: role.to_owned(),
            keyids: delegated.keyids.clone(),
            threshold: delegated.threshold,
            keys: delegations.keys.clone(),
            rules: root.signatories.clone(),
        })
    }

    fn with_quorum<T>(&self, use_quorum: impl FnOnce(&Quorum<'_>) -> T) -> Result<T, Malformed> {
        let ring = KeyRing::new(&self.keys)?;
        let quorum = Quorum::new(&self.role, &self.keyids, self.threshold, &ring, &self.rules)?;
        Ok(use_quorum(&quorum))
    }
}

impl Requirement {
    /// What a first root, version 1, must carry: its own root threshold (§5).
    pub fn first_root(staged: &[u8]) -> Result<Self, CeremonyError> {
        expect_kind(staged, Kind::Root)?;
        let first = open_envelope::<Root>(staged)?.body;
        if first.version != 1 {
            return Err(CeremonyError::NotFirstVersion { staged: first.version });
        }
        let label = format!("root version {}", first.version);
        Self::checked(Kind::Root, vec![Threshold::top_level(&first, "root", label)?])
    }

    /// What root version N+1 must carry: the root threshold of version N,
    /// `trusted_root`, and its own (§5).
    pub fn next_root(staged: &[u8], trusted_root: &[u8]) -> Result<Self, CeremonyError> {
        expect_kind(staged, Kind::Root)?;
        let trusted = open_envelope::<Root>(trusted_root)?.body;
        let next = open_envelope::<Root>(staged)?.body;
        if trusted.version.checked_add(1) != Some(next.version) {
            return Err(CeremonyError::NotNextVersion { trusted: trusted.version, staged: next.version });
        }
        Self::checked(
            Kind::Root,
            vec![
                Threshold::top_level(&trusted, "root", format!("root version {}", trusted.version))?,
                Threshold::top_level(&next, "root", format!("root version {}", next.version))?,
            ],
        )
    }

    /// What the top-level targets file must carry under `root`.
    pub fn targets(staged: &[u8], root: &[u8]) -> Result<Self, CeremonyError> {
        expect_kind(staged, Kind::Targets)?;
        let root = open_envelope::<Root>(root)?.body;
        Self::checked(Kind::Targets, vec![Threshold::top_level(&root, "targets", "targets".to_owned())?])
    }

    /// What delegated role `role`'s file must carry, under `root` and the
    /// targets file `delegator` that delegates it.
    pub fn delegated_targets(staged: &[u8], root: &[u8], delegator: &[u8], role: &str) -> Result<Self, CeremonyError> {
        expect_kind(staged, Kind::Targets)?;
        let root = open_envelope::<Root>(root)?.body;
        let mut threshold = Threshold::delegated(&root, delegator, role)?;
        if root.public_audiences.contains(role) && open_envelope::<Targets>(staged)?.body.delegates() {
            threshold.threshold = threshold.with_quorum(|quorum| quorum.signatory_count())?;
        }
        Self::checked(Kind::Targets, vec![threshold])
    }

    /// A requirement whose every threshold the verifier's own quorum accepts.
    fn checked(kind: Kind, thresholds: Vec<Threshold>) -> Result<Self, CeremonyError> {
        for threshold in &thresholds {
            threshold.with_quorum(|_| ())?;
        }
        Ok(Self { kind, thresholds })
    }

    /// Every key id that a threshold's role lists for `identity`, with its key.
    fn listed(&self, identity: &PublicIdentity) -> BTreeMap<String, Key> {
        let mut found = BTreeMap::new();
        for threshold in &self.thresholds {
            for keyid in &threshold.keyids {
                let listed = threshold.keys.get(keyid).filter(|l| public_identity(&l.key) == *identity);
                if let Some(listed) = listed {
                    found.insert(keyid.clone(), listed.key.clone());
                }
            }
        }
        found
    }

    /// The role whose file this requirement checks: every threshold is the
    /// rule of that one role, from one or two files that state it.
    pub fn role(&self) -> &str {
        self.thresholds.first().map_or("", |threshold| threshold.role.as_str())
    }

    fn open(&self, staged: &[u8]) -> Result<Opened, CeremonyError> {
        Ok(match self.kind {
            Kind::Root => Opened::of(open_envelope::<Root>(staged)?, None),
            Kind::Targets => {
                let envelope = open_envelope::<Targets>(staged)?;
                let targets = envelope.body.clone();
                Opened::of(envelope, Some(targets))
            }
            Kind::Snapshot => Opened::of(open_envelope::<Snapshot>(staged)?, None),
            Kind::Timestamp => Opened::of(open_envelope::<Timestamp>(staged)?, None),
        })
    }
}

/// Refuses a staged file that is not of the kind a constructor checks.
fn expect_kind(staged: &[u8], expected: Kind) -> Result<(), CeremonyError> {
    let found = staged_kind(&StagedFile::read(staged)?.signed)?;
    if found != expected {
        return Err(CeremonyError::WrongKind { expected: expected.name(), found: found.name().to_owned() });
    }
    Ok(())
}

/// A staged file opened as the verifier opens it.
struct Opened {
    kind: &'static str,
    version: u64,
    canonical: Vec<u8>,
    signatures: Vec<Signature>,
    targets: Option<Targets>,
}

impl Opened {
    fn of<T: Typed>(envelope: Envelope<T>, targets: Option<Targets>) -> Self {
        let (kind, version) = (T::TYPE, envelope.body.version());
        Self { kind, version, canonical: envelope.canonical, signatures: envelope.signatures, targets }
    }

    fn covered(&self) -> Covered<'_> {
        Covered { kind: self.kind, version: self.version, canonical: &self.canonical }
    }
}
```

## The status

The status is the verifier's tally for each threshold, kept even while it
falls short. It lists every signatory the role names, so a ceremony shows
both who has signed and who is still missing. For a targets version that
delegates, it also gives each delegation as the file writes it: the role
it names, its patterns, its key ids and its threshold (§8). A signer then
reviews the grant itself, not a summary of it.

<a name="chunk-standing"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#standing`</sub>

```rust {#standing}
/// How one threshold of a staged file stands (§5, step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    /// The role and where its rule comes from, such as `root version 3`.
    pub label: String,
    pub threshold: u64,
    pub counted: u64,
    /// Every signatory the role lists.
    pub signatories: Vec<SignatoryVerdict>,
}

impl Standing {
    pub fn met(&self) -> bool {
        self.counted >= self.threshold
    }

    /// The signatories who do not count yet.
    pub fn missing(&self) -> impl Iterator<Item = &str> {
        self.signatories.iter().filter(|v| !v.counted).map(|v| v.signatory.as_str())
    }
}

impl Requirement {
    /// How each threshold stands with the signatures that `staged` carries.
    pub fn standing(&self, staged: &[u8]) -> Result<Vec<Standing>, CeremonyError> {
        let opened = self.open(staged)?;
        let mut standings = Vec::new();
        for threshold in &self.thresholds {
            let tally = threshold.with_quorum(|quorum| quorum.tally(&opened.covered(), &opened.signatures))?;
            standings.push(Standing {
                label: threshold.label.clone(),
                threshold: threshold.threshold,
                counted: tally.counted,
                signatories: tally.verdicts,
            });
        }
        Ok(standings)
    }

    /// The delegations a staged targets version makes, for its signers to review.
    pub fn delegations(&self, staged: &[u8]) -> Result<Vec<DelegatedRole>, CeremonyError> {
        let targets = self.open(staged)?.targets;
        Ok(targets.and_then(|t| t.delegations).map(|d| d.roles).unwrap_or_default())
    }
}
```

## Signing

`sign` hands the signer program what the staged files' signatures cover,
the namespace and the key the signer named, and takes an armored SSHSIG
signature back (§7). One file is signed with a single signature: the
program signs the canonical bytes of its body under `release-metadata`.
Several files are signed with one batch signature: the program signs the
batch statement that lists them, under `release-metadata-batch`, so a
security key is touched once for all of them
(`implementation:release-metadata/release-metadata`, "Batch signatures").
Each file's role in the statement is the role its requirement checks.

`sign` never reads the key. It learns which key signed from the public key
inside the envelope, and adds the signature to each file under every key
id that a threshold of that file lists for that key, so a key that the old
and the new root list differently still counts for both. A batch entry
also carries the statement. Before adding a signature, `sign` checks it
with the verifier's own check of a signature entry, so a signature that
would not count is refused here and not by the readers later. Every file
is checked before any is returned, and a key that some file's thresholds
do not list is refused, naming the role; the caller writes all the files
or none.

A targets file is checked against the rebuild first, and the signer
program is not called when the check fails.

<a name="chunk-sign"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#sign`</sub>

```rust {#sign}
/// One staged file to sign: the file, the thresholds it must meet, and the
/// rebuild its targets entries are checked against (§6).
#[derive(Clone, Copy)]
pub struct Staged<'a> {
    pub file: &'a [u8],
    pub requirement: &'a Requirement,
    pub rebuild: &'a Rebuild,
}

/// Signs `files` through `signer` with the key that `key` names, with one
/// call to the signer, and returns each file with the new signature, in
/// order (§5, step 2). One file gets a single signature; several get one
/// batch signature that counts on each (§3). A targets file is signed only
/// when its rebuild holds (§6).
pub fn sign(files: &[Staged<'_>], signer: &dyn Signer, key: &Path) -> Result<Vec<Vec<u8>>, CeremonyError> {
    let opened = files.iter().map(|file| file.requirement.open(file.file)).collect::<Result<Vec<_>, _>>()?;
    for file in files {
        let alongside: Vec<&Targets> = files
            .iter()
            .zip(&opened)
            .filter(|(other, _)| std::ptr::eq(other.rebuild, file.rebuild))
            .filter_map(|(_, opened)| opened.targets.as_ref())
            .collect();
        file.rebuild.check(&alongside)?;
    }
    let (namespace, message, statement) = match opened.as_slice() {
        [] => return Err(CeremonyError::NothingToSign),
        [one] => (NAMESPACE, one.canonical.clone(), None),
        many => {
            let statement = batch_statement(files, many)?;
            (BATCH_NAMESPACE, canonical_json(&statement)?, Some(statement))
        }
    };
    let armored = signer.sign(key, namespace, &message)?;
    let blob = unarmor_sshsig(&armored).ok_or(CeremonyError::Armor)?;
    let envelope = parse_sshsig(&blob).ok_or(CeremonyError::Armor)?;
    let identity = PublicIdentity::Decoded(envelope.public_key.to_vec());
    let sig = hex::encode(&blob);
    let mut signed = Vec::new();
    for (file, opened) in files.iter().zip(&opened) {
        let role = file.requirement.role();
        let listed = file.requirement.listed(&identity);
        if listed.is_empty() {
            return Err(CeremonyError::KeyNotListed { role: role.to_owned() });
        }
        let mut staged = StagedFile::read(file.file)?;
        for (keyid, key) in listed {
            let signature = Signature { keyid, sig: sig.clone(), batch: statement.clone() };
            check_entry(&key, role, &opened.covered(), &signature)?;
            staged.signatures.retain(|existing| existing.keyid != signature.keyid);
            staged.signatures.push(signature);
        }
        tracing::debug!(role, signatures = staged.signatures.len(), "release_metadata.ceremony.signed");
        signed.push(staged.write()?);
    }
    Ok(signed)
}

/// The batch statement over `opened`, refusing a file given twice.
fn batch_statement(files: &[Staged<'_>], opened: &[Opened]) -> Result<Value, CeremonyError> {
    let mut seen = BTreeSet::new();
    let mut listings = Vec::new();
    for (file, opened) in files.iter().zip(opened) {
        let role = file.requirement.role();
        if !seen.insert((opened.kind, role)) {
            return Err(CeremonyError::RepeatedFile { kind: opened.kind, role: role.to_owned() });
        }
        listings.push(batch::listing(&opened.covered(), role));
    }
    Ok(batch::statement(listings))
}

/// The binary SSHSIG inside `ssh-keygen -Y sign`'s armor.
fn unarmor_sshsig(armored: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(armored).ok()?.trim();
    let body = text
        .strip_prefix("-----BEGIN SSH SIGNATURE-----")?
        .strip_suffix("-----END SSH SIGNATURE-----")?;
    Base64::decode_vec(&body.split_whitespace().collect::<String>()).ok()
}
```

## The rebuild check

A build server that an attacker controls can make a bad artifact and a
correct targets entry for it (§6). Where the build is reproducible, the
signer rebuilds each artifact from the tagged source on their own machine
and hands the results to `sign`. Every entry of the targets files signed
with those results must then have a rebuild, with the entry's length and
every hash it lists. A rebuild for a path that none of those files lists
is refused too, since the signer meant to check something that is not
there. Where the build is not
reproducible, the signer says so with `Rebuild::NotReproducible`; the
command has no silent default, so a signer who forgot to rebuild is
refused rather than trusted.

<a name="chunk-rebuild"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#rebuild`</sub>

```rust {#rebuild}
/// What the signer checked about how a targets file's artifacts were built (§6).
#[derive(Debug, Clone)]
pub enum Rebuild {
    /// The artifacts the signer rebuilt from the tagged source, by target
    /// path. Every entry needs one, and must match it.
    Rebuilt(BTreeMap<String, Vec<u8>>),
    /// The publisher's build is not reproducible: the signature approves the
    /// release and attests nothing about its build.
    NotReproducible,
}

impl Rebuild {
    /// Checks the targets files signed with this rebuild.
    fn check(&self, files: &[&Targets]) -> Result<(), CeremonyError> {
        let Rebuild::Rebuilt(artifacts) = self else {
            return Ok(());
        };
        let listed = |path: &String| files.iter().any(|targets| targets.targets.contains_key(path));
        if let Some(path) = artifacts.keys().find(|path| !listed(path)) {
            return Err(CeremonyError::RebuiltUnlisted { path: path.clone() });
        }
        for (path, entry) in files.iter().flat_map(|targets| &targets.targets) {
            let bytes = artifacts.get(path).ok_or_else(|| CeremonyError::NotRebuilt { path: path.clone() })?;
            let rebuilt_length = bytes.len() as u64;
            if rebuilt_length != entry.length {
                let (path, listed) = (path.clone(), entry.length);
                return Err(CeremonyError::RebuildLength { path, listed, rebuilt: rebuilt_length });
            }
            for (algorithm, listed) in &entry.hashes {
                let rebuilt = hex_digest(algorithm, bytes).ok_or_else(|| Malformed::HashAlgorithm(algorithm.clone()))?;
                if !rebuilt.eq_ignore_ascii_case(listed) {
                    return Err(CeremonyError::RebuildMismatch {
                        path: path.clone(),
                        algorithm: algorithm.clone(),
                        listed: listed.clone(),
                        rebuilt,
                    });
                }
            }
        }
        Ok(())
    }
}
```

## The online roles

The snapshot and the timestamp change on every release and, for the
timestamp, every few hours, so one online key signs both (§6). The crate
builds and signs them, through the same signer program as the people's
files, so the build server's scheduled job is one call:

- `sign_snapshot` lists each targets file it is given, top-level and
  delegated, by role name, with the file's version, length and SHA-256.
- `sign_timestamp` lists the snapshot it is given the same way.

Each takes the previous file of its role, when there is one, and writes
version one more than it; without one it writes version 1. Each takes the
expiry as a time, which the caller reads from its own clock, since the
crate reads none. Re-signing the timestamp with a later expiry over the
same snapshot is the refresh a scheduled job runs.

Both sign through `sign`, under the root's snapshot or timestamp role, so
the signature is checked against the online key's listing before the file
is returned. The signer program makes SSHSIG, so the online key's object
uses an SSHSIG scheme, `sshsig-ssh-ed25519` for one software key. A TUF
`ed25519` online key is signed by other means.

<a name="chunk-online"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#online`</sub>

```rust {#online}
/// The TUF specification version the files this crate writes declare.
const SPEC_VERSION: &str = "1.0.37";

/// Builds and signs a snapshot that lists `targets`, every targets file by
/// role name (`targets` and each delegated role), through `signer` with the
/// key that `key` names (§6). Its version is one more than `previous`'s, or
/// 1, and it expires at `expires`.
pub fn sign_snapshot(
    root: &[u8],
    previous: Option<&[u8]>,
    targets: &BTreeMap<String, Vec<u8>>,
    expires: SystemTime,
    signer: &dyn Signer,
    key: &Path,
) -> Result<Vec<u8>, CeremonyError> {
    let mut meta = Map::new();
    for (role, bytes) in targets {
        let version = open_envelope::<Targets>(bytes)?.body.version;
        meta.insert(format!("{role}.json"), meta_entry(version, bytes));
    }
    let version = next_version::<Snapshot>(previous)?;
    let body = json!({
        "_type": "snapshot", "spec_version": SPEC_VERSION, "version": version,
        "expires": format_utc(expires)?, "meta": meta,
    });
    sign_online(Kind::Snapshot, root, body, signer, key)
}

/// Builds and signs a timestamp that lists `snapshot`, through `signer`
/// with the key that `key` names (§6). Its version is one more than
/// `previous`'s, or 1, and it expires at `expires`. Called with the current
/// timestamp as `previous` and the same snapshot, it is the refresh.
pub fn sign_timestamp(
    root: &[u8],
    previous: Option<&[u8]>,
    snapshot: &[u8],
    expires: SystemTime,
    signer: &dyn Signer,
    key: &Path,
) -> Result<Vec<u8>, CeremonyError> {
    let snapshot_version = open_envelope::<Snapshot>(snapshot)?.body.version;
    let version = next_version::<Timestamp>(previous)?;
    let body = json!({
        "_type": "timestamp", "spec_version": SPEC_VERSION, "version": version,
        "expires": format_utc(expires)?,
        "meta": { "snapshot.json": meta_entry(snapshot_version, snapshot) },
    });
    sign_online(Kind::Timestamp, root, body, signer, key)
}

/// One listed file: its version, length and SHA-256.
fn meta_entry(version: u64, bytes: &[u8]) -> Value {
    json!({ "version": version, "length": bytes.len(), "hashes": { "sha256": hex::encode(Sha256::digest(bytes)) } })
}

/// One listed file by its version only, for a file signed in the same batch
/// as its lister (§6).
fn version_entry(version: u64) -> Value {
    json!({ "version": version })
}

/// An online role's unsigned file and the threshold it must meet under `root`.
fn online_file(kind: Kind, root: &Root, body: Value) -> Result<(Vec<u8>, Requirement), CeremonyError> {
    let file = StagedFile { signed: body, signatures: Vec::new() }.write()?;
    let role = kind.name();
    let requirement = Requirement::checked(kind, vec![Threshold::top_level(root, role, role.to_owned())?])?;
    Ok((file, requirement))
}

fn sign_online(kind: Kind, root: &[u8], body: Value, signer: &dyn Signer, key: &Path) -> Result<Vec<u8>, CeremonyError> {
    let (file, requirement) = online_file(kind, &open_envelope::<Root>(root)?.body, body)?;
    let rebuild = Rebuild::Rebuilt(BTreeMap::new());
    let staged = Staged { file: &file, requirement: &requirement, rebuild: &rebuild };
    let mut signed = sign(&[staged], signer, key)?;
    signed.pop().ok_or(CeremonyError::NothingToSign)
}

/// The version one more than `previous`'s, or 1 for the first file of a role.
fn next_version<T: Typed + serde::de::DeserializeOwned>(previous: Option<&[u8]>) -> Result<u64, CeremonyError> {
    Ok(match previous {
        Some(previous) => open_envelope::<T>(previous)?.body.version().saturating_add(1),
        None => 1,
    })
}
```

## A release in one touch

A maintainer who signs a release and whose key the root also lists for the
snapshot and the timestamp signs all three in one batch (§3, §6).
`sign_release` takes the staged targets file of the release's role, the
other targets files the snapshot lists, the previous snapshot and
timestamp, and their expiries. It builds the snapshot and the timestamp,
and signs the three with one call to the signer, so a security key is
touched once. The snapshot lists the role's file by version only and every
other targets file by version, length and SHA-256, as `sign_snapshot`
does; the timestamp lists the snapshot by version only. Those are the
files whose signature is made in the same step as their lister's. The
targets file meets its role's threshold as `sign` checks it: from the root
for the top-level role, or from the file that delegates an audience.

<a name="chunk-release"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#release`</sub>

```rust {#release}
/// A release to sign in one batch: the staged targets file of `role`, and
/// what its snapshot and timestamp are built from (§3, §6).
#[derive(Clone, Copy)]
pub struct Release<'a> {
    /// The trusted root, whose roles list the signer's key.
    pub root: &'a [u8],
    /// `targets` for the top-level role, or a delegated role's name.
    pub role: &'a str,
    /// The staged targets file of `role`.
    pub staged: &'a [u8],
    /// The targets file that delegates `role`; `None` for `targets` itself.
    pub delegator: Option<&'a [u8]>,
    pub rebuild: &'a Rebuild,
    /// The other targets files the snapshot lists, by role name.
    pub listed: &'a BTreeMap<String, Vec<u8>>,
    pub previous_snapshot: Option<&'a [u8]>,
    pub previous_timestamp: Option<&'a [u8]>,
    pub snapshot_expires: SystemTime,
    pub timestamp_expires: SystemTime,
}

/// A release's three files, each carrying the one batch signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRelease {
    pub targets: Vec<u8>,
    pub snapshot: Vec<u8>,
    pub timestamp: Vec<u8>,
}

/// Signs a release's targets file, snapshot and timestamp with one batch
/// signature, through `signer` with the key that `key` names (§3, §6).
pub fn sign_release(release: &Release<'_>, signer: &dyn Signer, key: &Path) -> Result<SignedRelease, CeremonyError> {
    let requirement = match release.delegator {
        None => Requirement::targets(release.staged, release.root)?,
        Some(delegator) => Requirement::delegated_targets(release.staged, release.root, delegator, release.role)?,
    };
    let root = open_envelope::<Root>(release.root)?.body;
    let mut meta = Map::new();
    for (role, bytes) in release.listed.iter().filter(|(role, _)| role.as_str() != release.role) {
        meta.insert(format!("{role}.json"), meta_entry(open_envelope::<Targets>(bytes)?.body.version, bytes));
    }
    let version = open_envelope::<Targets>(release.staged)?.body.version;
    meta.insert(format!("{}.json", release.role), version_entry(version));
    let snapshot_version = next_version::<Snapshot>(release.previous_snapshot)?;
    let snapshot = json!({
        "_type": "snapshot", "spec_version": SPEC_VERSION, "version": snapshot_version,
        "expires": format_utc(release.snapshot_expires)?, "meta": meta,
    });
    let timestamp = json!({
        "_type": "timestamp", "spec_version": SPEC_VERSION,
        "version": next_version::<Timestamp>(release.previous_timestamp)?,
        "expires": format_utc(release.timestamp_expires)?,
        "meta": { "snapshot.json": version_entry(snapshot_version) },
    });
    let (snapshot, snapshot_requirement) = online_file(Kind::Snapshot, &root, snapshot)?;
    let (timestamp, timestamp_requirement) = online_file(Kind::Timestamp, &root, timestamp)?;
    let none = Rebuild::Rebuilt(BTreeMap::new());
    let files = [
        Staged { file: release.staged, requirement: &requirement, rebuild: release.rebuild },
        Staged { file: &snapshot, requirement: &snapshot_requirement, rebuild: &none },
        Staged { file: &timestamp, requirement: &timestamp_requirement, rebuild: &none },
    ];
    let mut signed = sign(&files, signer, key)?.into_iter();
    let mut next = || signed.next().ok_or(CeremonyError::NothingToSign);
    Ok(SignedRelease { targets: next()?, snapshot: next()?, timestamp: next()? })
}
```

A root ceremony is the other place a signer signs two files at once: a new
root, and the top-level targets file under it, when the root's change
reaches the targets role, such as a first root, or a new targets key.
`sign_ceremony` signs both with one batch signature. The targets file is
checked under the staged root, since that is the root a reader will hold
when it reads that targets file. A signer whose key only one of the two
files' thresholds lists is refused, naming the other's role; such a signer
signs their one file with `sign`.

<a name="chunk-release-2"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#release` · continues</sub>

```rust {#release}

/// A root and the top-level targets file under it, each carrying the one
/// batch signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCeremony {
    pub root: Vec<u8>,
    pub targets: Vec<u8>,
}

/// Signs a staged root and the staged top-level targets file under it with
/// one batch signature (§3, §5). `trusted_root` is the root version before
/// it, or `None` for a first root.
pub fn sign_ceremony(
    root: &[u8],
    trusted_root: Option<&[u8]>,
    targets: &[u8],
    rebuild: &Rebuild,
    signer: &dyn Signer,
    key: &Path,
) -> Result<SignedCeremony, CeremonyError> {
    let root_requirement = match trusted_root {
        None => Requirement::first_root(root)?,
        Some(trusted) => Requirement::next_root(root, trusted)?,
    };
    let targets_requirement = Requirement::targets(targets, root)?;
    let none = Rebuild::Rebuilt(BTreeMap::new());
    let files = [
        Staged { file: root, requirement: &root_requirement, rebuild: &none },
        Staged { file: targets, requirement: &targets_requirement, rebuild },
    ];
    let mut signed = sign(&files, signer, key)?.into_iter();
    let mut next = || signed.next().ok_or(CeremonyError::NothingToSign);
    Ok(SignedCeremony { root: next()?, targets: next()? })
}
```

## The signer program

The commands sign through a program with `ssh-keygen -Y sign`'s interface
(§7): `<program> -Y sign -n <namespace> -f <key>`, the message on its
standard input and the armored signature on its standard output. git signs
commits through the same interface (`gpg.ssh.program`). `ssh-keygen` is the
default, and it reaches a FIDO2 token, a key file or an SSH agent such as
Secretive. The program's standard error is read line by line as the
program writes it. An embedder that signs in front of a person hands
`SignerProgram::with_output` a sink, and each line reaches it while the
program still runs: a security key's "Confirm user presence for key …"
appears while the key waits for its touch. Without a sink nothing is
shown, so a scheduled job that refreshes the timestamp stays quiet,
though `ssh-keygen` writes "Signing data on standard input" for every
signature. Either way the text is kept, and a program that fails returns
it in its error. A passphrase prompt goes to the terminal itself, not to
standard error, and reaches the signer regardless. Only the signer
program knows whether a key waits for a touch, so the embedder shows the
program's own line instead of a guess of its own.

`Signer` is the library's seam: an embedder can sign some other way, such
as x0k's approver client, and the commands use `SignerProgram`. This is
the one file of the crate that runs a program.

<a name="chunk-signer"></a><sub>[`src/signer.rs`](../../crates/x0k-release-metadata/src/signer.rs) · `#signer`</sub>

```rust {#signer file="src/signer.rs"}
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::panic::RefUnwindSafe;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;

/// Makes an SSHSIG signature, as `ssh-keygen -Y sign` does (decision §7).
pub trait Signer {
    /// Signs `message` under `namespace` with the key that `key` names, and
    /// returns the armored signature.
    fn sign(&self, key: &Path, namespace: &str, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// Where the lines of a signer program's standard error go, one at a time.
/// `RefUnwindSafe` keeps `SignerProgram` as unwind-safe as it was without a
/// sink.
type OutputSink = Arc<dyn Fn(&str) + Send + Sync + RefUnwindSafe>;

/// A program called as `<program> -Y sign -n <namespace> -f <key>`, with the
/// message on its standard input and the signature on its standard output.
#[derive(Clone)]
pub struct SignerProgram {
    program: OsString,
    output: Option<OutputSink>,
}

impl SignerProgram {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self { program: program.into(), output: None }
    }

    /// Hands each line the program writes to its standard error to `sink`
    /// while the program runs, such as a security key's request for a
    /// touch. Without a sink the program's standard error is shown nowhere
    /// and kept only for a failure.
    pub fn with_output(mut self, sink: impl Fn(&str) + Send + Sync + RefUnwindSafe + 'static) -> Self {
        self.output = Some(Arc::new(sink));
        self
    }
}

impl std::fmt::Debug for SignerProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerProgram")
            .field("program", &self.program)
            .field("output", &self.output.as_ref().map(|_| "sink"))
            .finish()
    }
}

impl Default for SignerProgram {
    fn default() -> Self {
        Self::new("ssh-keygen")
    }
}

impl Signer for SignerProgram {
    fn sign(&self, key: &Path, namespace: &str, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let mut child = Command::new(&self.program)
            .args(["-Y", "sign", "-n", namespace, "-f"])
            .arg(key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(SignerError::Spawn)?;
        let (stderr, sink) = (child.stderr.take(), self.output.clone());
        let reader = thread::spawn(move || {
            let mut text = String::new();
            for line in stderr.map(BufReader::new).into_iter().flat_map(BufRead::lines).map_while(Result::ok) {
                if let Some(sink) = &sink {
                    sink(&line);
                }
                text.push_str(&line);
                text.push('\n');
            }
            text
        });
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(message).map_err(SignerError::Io)?;
        }
        let output = child.wait_with_output().map_err(SignerError::Io)?;
        let stderr = reader.join().unwrap_or_default();
        if !output.status.success() {
            let stderr = stderr.trim().to_owned();
            return Err(SignerError::Failed { status: output.status, stderr });
        }
        Ok(output.stdout)
    }
}

/// Why the signer program made no signature.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    #[error("cannot start it: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("cannot pass it the message or read its signature: {0}")]
    Io(#[source] std::io::Error),
    #[error("it failed ({status}): {stderr}")]
    Failed { status: ExitStatus, stderr: String },
}
```

## The commands

The program reads and writes the files, reads the clock for `stage` and
for the expiries, and prints the status; the steps are the library's.
`sign` writes each staged file in place and prints its status after the
new signature, one block per file headed by its path, so each signer sees
what remains. The status ends with one line per delegation:
`delegates <role>: paths <patterns>; keys <key ids>; threshold <n>`.
`status` exits 0 when every threshold is met, 1 while a signatory is
missing, and 2 on an error, so a script can wait for the ceremony to
finish.

```
x0k-release-metadata stage 2.root.body.json 2.root.json
x0k-release-metadata sign 2.root.json --trusted 1.root.json --key ~/.ssh/id_ed25519_sk
x0k-release-metadata status 2.root.json --trusted 1.root.json
```

A first root takes no `--trusted`, since nothing came before it:

```
x0k-release-metadata stage 1.root.body.json 1.root.json
x0k-release-metadata sign 1.root.json --key ~/.ssh/id_ed25519_sk
x0k-release-metadata status 1.root.json
```

`sign` takes several staged files and signs them with one batch
signature, one touch of a security key. A root signed with the top-level
targets file under it is the common case. A staged root in the same call
is the root its targets files are checked under, and a top-level
`targets.json` in the same call is the file that delegates the audiences
of the others; otherwise `--trusted` and `--delegator` name them. A
targets file's role is its name as TUF names it, `<role>.json` or
`<version>.<role>.json`, or `--role` when one targets file is given.

```
x0k-release-metadata sign 2.root.json targets.json --trusted 1.root.json --key ~/.ssh/id_ed25519_sk
```

A delegated targets file names the file that delegates it, and a targets
file is signed with the rebuilt artifacts or with `--not-reproducible`. A
targets version that delegates is staged with its role:

```
x0k-release-metadata stage fleet.body.json fleet.json --role fleet
x0k-release-metadata sign fleet.json --trusted root.json --delegator targets.json \
    --role fleet --key ~/.ssh/id_ed25519 --rebuilt fleet/chariot-1.0.tar=target/chariot-1.0.tar
```

A maintainer whose key the root also lists for the snapshot and the
timestamp releases with one touch. `release` signs the staged targets file,
writes the snapshot and the timestamp beside it, and signs the three
together. The files at `--snapshot` and `--timestamp` are the previous
ones, when they exist, and are replaced:

```
x0k-release-metadata release fleet.json --trusted root.json --delegator targets.json \
    --targets targets.json --snapshot snapshot.json --timestamp timestamp.json \
    --snapshot-expires-in 7d --timestamp-expires-in 1d --key ~/.ssh/id_ed25519_sk \
    --rebuilt fleet/chariot-1.0.tar=target/chariot-1.0.tar
```

The build server signs the online roles with its one key. A scheduled
refresh re-signs the timestamp over the same snapshot, one version up:

```
x0k-release-metadata snapshot snapshot.json --trusted root.json --targets targets.json --targets stable.json \
    --previous snapshot.json --expires-in 7d --key online_ed25519
x0k-release-metadata timestamp timestamp.json --trusted root.json --snapshot snapshot.json \
    --previous timestamp.json --expires-in 1d --key online_ed25519
```

<a name="chunk-cli"></a><sub>[`src/bin/x0k-release-metadata.rs`](../../crates/x0k-release-metadata/src/bin/x0k-release-metadata.rs) · `#cli` · assembles [cli-arguments](#chunk-cli-arguments) · [cli-files](#chunk-cli-files) · [cli-requirements](#chunk-cli-requirements) · [cli-commands](#chunk-cli-commands)</sub>

```rust {#cli file="src/bin/x0k-release-metadata.rs"}
//! The ceremony commands of decision §5: stage, sign and status, and the
//! release and online roles of §6.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use x0k_release_metadata::{
    sign, sign_release, sign_snapshot, sign_timestamp, stage, CeremonyError, DelegatedRole, Rebuild, Release,
    Requirement, SignerProgram, Staged, Standing,
};

const USAGE: &str = "\
usage:
  x0k-release-metadata stage <body.json> <staged.json> [--role <name>]
  x0k-release-metadata status <staged.json> [--trusted <root.json>] [--delegator <targets.json>] [--role <name>]
  x0k-release-metadata sign <staged.json>... [--trusted <root.json>] [--delegator <targets.json>] [--role <name>]
      --key <key file> [--signer <program>] [--rebuilt <target path>=<file>]... [--not-reproducible]
  x0k-release-metadata release <role>.json --trusted <root.json> [--delegator <targets.json>] [--role <name>]
      [--targets <role>.json]... --snapshot <snapshot.json> --timestamp <timestamp.json>
      --snapshot-expires-in <hours>h|<days>d --timestamp-expires-in <hours>h|<days>d
      --key <key file> [--signer <program>] [--rebuilt <target path>=<file>]... [--not-reproducible]
  x0k-release-metadata snapshot <snapshot.json> --trusted <root.json> --targets <role>.json...
      [--previous <snapshot.json>] --expires-in <hours>h|<days>d --key <key file> [--signer <program>]
  x0k-release-metadata timestamp <timestamp.json> --trusted <root.json> --snapshot <snapshot.json>
      [--previous <timestamp.json>] --expires-in <hours>h|<days>d --key <key file> [--signer <program>]

A root without --trusted is a first root, version 1. Several staged files
are signed with one signature. A targets file's role is its name,
<role>.json, or --role.
";

#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error("{0}")]
    Usage(&'static str),
    #[error("{path}: {source}")]
    File {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Ceremony(#[from] CeremonyError),
    #[error("cannot write the status: {0}")]
    Status(#[source] std::io::Error),
    #[error("not a metadata file: {0}")]
    NotMetadata(#[source] serde_json::Error),
}

<<cli-arguments>>

<<cli-files>>

<<cli-requirements>>

<<cli-commands>>

fn main() -> ExitCode {
    match parse_ceremony_arguments(std::env::args().skip(1)).and_then(|args| run_ceremony_command(&args)) {
        Ok(code) => code,
        Err(error) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "x0k-release-metadata: {error}");
            if matches!(error, CommandError::Usage(_)) {
                let _ = write!(stderr, "{USAGE}");
            }
            ExitCode::from(2)
        }
    }
}
```

The arguments are few, so the program parses them itself rather than take
a parser crate.

<a name="chunk-cli-arguments"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#cli-arguments`</sub>

```rust {#cli-arguments}
/// The command line: positional words, and each option's values.
struct Arguments {
    positional: Vec<String>,
    options: BTreeMap<String, Vec<String>>,
    not_reproducible: bool,
}

fn parse_ceremony_arguments(mut args: impl Iterator<Item = String>) -> Result<Arguments, CommandError> {
    const WITH_VALUE: [&str; 13] = [
        "--trusted", "--delegator", "--role", "--key", "--signer", "--rebuilt", "--targets", "--snapshot", "--timestamp",
        "--previous", "--expires-in", "--snapshot-expires-in", "--timestamp-expires-in",
    ];
    let mut parsed = Arguments { positional: Vec::new(), options: BTreeMap::new(), not_reproducible: false };
    while let Some(arg) = args.next() {
        if arg == "--not-reproducible" {
            parsed.not_reproducible = true;
        } else if WITH_VALUE.contains(&arg.as_str()) {
            let value = args.next().ok_or(CommandError::Usage("an option lacks its value"))?;
            parsed.options.entry(arg).or_default().push(value);
        } else if arg.starts_with("--") {
            return Err(CommandError::Usage("unknown option"));
        } else {
            parsed.positional.push(arg);
        }
    }
    Ok(parsed)
}

impl Arguments {
    fn one(&self, name: &str) -> Result<Option<&str>, CommandError> {
        match self.options.get(name).map(Vec::as_slice) {
            None => Ok(None),
            Some([value]) => Ok(Some(value.as_str())),
            Some(_) => Err(CommandError::Usage("an option is given twice")),
        }
    }

    fn required(&self, name: &str) -> Result<&str, CommandError> {
        self.one(name)?.ok_or(CommandError::Usage("a required option is missing"))
    }

    fn all(&self, name: &str) -> &[String] {
        self.options.get(name).map(Vec::as_slice).unwrap_or_default()
    }
}
```

A file's role comes from its name the way TUF names metadata files:
`stable.json`, or `3.stable.json` in a repository with consistent
snapshots.

<a name="chunk-cli-files"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#cli-files`</sub>

```rust {#cli-files}
fn read_ceremony_file(path: &Path) -> Result<Vec<u8>, CommandError> {
    fs::read(path).map_err(|source| CommandError::File { path: path.to_owned(), source })
}

/// The file at `path`, or `None` when there is none yet.
fn read_if_present(path: &Path) -> Result<Option<Vec<u8>>, CommandError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CommandError::File { path: path.to_owned(), source }),
    }
}

fn write_ceremony_file(path: &Path, bytes: &[u8]) -> Result<(), CommandError> {
    fs::write(path, bytes).map_err(|source| CommandError::File { path: path.to_owned(), source })
}

/// A metadata file's body, read only for its kind and version.
#[derive(Deserialize)]
struct Header {
    signed: HeaderBody,
}

#[derive(Deserialize)]
struct HeaderBody {
    #[serde(rename = "_type")]
    kind: String,
    #[serde(default)]
    version: u64,
    #[serde(default)]
    expires: String,
}

fn header_of(bytes: &[u8]) -> Result<HeaderBody, CommandError> {
    Ok(serde_json::from_slice::<Header>(bytes).map_err(CommandError::NotMetadata)?.signed)
}

fn optional_file(args: &Arguments, name: &str) -> Result<Option<Vec<u8>>, CommandError> {
    args.one(name)?.map(|path| read_ceremony_file(Path::new(path))).transpose()
}

/// The role TUF's file name gives: `<role>.json`, or `<version>.<role>.json`.
fn role_named(path: &Path) -> Result<String, CommandError> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or(CommandError::Usage("a targets file is named <role>.json"))?;
    let role = match stem.split_once('.') {
        Some((version, role)) if !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()) => role,
        _ => stem,
    };
    Ok(role.to_owned())
}

/// The targets files `--targets` names, by role.
fn targets_files(args: &Arguments) -> Result<BTreeMap<String, Vec<u8>>, CommandError> {
    let mut targets = BTreeMap::new();
    for path in args.all("--targets") {
        let path = Path::new(path);
        targets.insert(role_named(path)?, read_ceremony_file(path)?);
    }
    Ok(targets)
}
```

What each staged file must carry follows from its kind, its role and the
files given with it. A root is checked against `--trusted`, or is a first
root. A targets file is checked under the root staged in the same call, or
`--trusted`; a delegated role's file also under the top-level targets file
staged in the same call, or `--delegator`.

<a name="chunk-cli-requirements"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#cli-requirements`</sub>

```rust {#cli-requirements}
/// The role a staged file is a version of: `root`, or a targets file's
/// `--role` or file name.
fn role_of(path: &Path, kind: &str, args: &Arguments) -> Result<String, CommandError> {
    match kind {
        "root" => Ok("root".to_owned()),
        "targets" => args.one("--role")?.map_or_else(|| role_named(path), |role| Ok(role.to_owned())),
        _ => Err(CommandError::Usage("status and sign take root and targets files")),
    }
}

/// What each staged file must carry, given the files staged with it.
fn requirements_for(paths: &[&Path], files: &[Vec<u8>], args: &Arguments) -> Result<Vec<Requirement>, CommandError> {
    let kinds = files.iter().map(|file| header_of(file).map(|h| h.kind)).collect::<Result<Vec<_>, _>>()?;
    if args.one("--role")?.is_some() && kinds.iter().filter(|kind| *kind == "targets").count() != 1 {
        return Err(CommandError::Usage("--role names the role of the one targets file it is given with"));
    }
    let roles = paths.iter().zip(&kinds).map(|(path, kind)| role_of(path, kind, args)).collect::<Result<Vec<_>, _>>()?;
    if roles.iter().filter(|role| *role == "root").count() > 1 {
        return Err(CommandError::Usage("one call signs one root"));
    }
    let trusted = optional_file(args, "--trusted")?;
    let delegator = optional_file(args, "--delegator")?;
    if delegator.is_some() && roles.iter().all(|role| role == "root" || role == "targets") {
        return Err(CommandError::Usage("--delegator goes with a delegated role's file"));
    }
    let staged = |wanted: &str| roles.iter().position(|role| role == wanted).map(|at| files[at].as_slice());
    let root = staged("root").or(trusted.as_deref());
    let delegating = staged("targets").or(delegator.as_deref());
    let mut requirements = Vec::new();
    for (file, role) in files.iter().zip(&roles) {
        let under_root = || root.ok_or(CommandError::Usage("a targets file takes --trusted <root.json>"));
        requirements.push(match role.as_str() {
            "root" => match &trusted {
                None => Requirement::first_root(file)?,
                Some(trusted) => Requirement::next_root(file, trusted)?,
            },
            "targets" => Requirement::targets(file, under_root()?)?,
            role => {
                let delegating = delegating.ok_or(CommandError::Usage("a delegated role's file takes --delegator <targets.json>"))?;
                Requirement::delegated_targets(file, under_root()?, delegating, role)?
            }
        });
    }
    Ok(requirements)
}
```

<a name="chunk-cli-commands"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#cli-commands` · assembles [cli-release](#chunk-cli-release)</sub>

```rust {#cli-commands}
/// The expiry the option `name` gives, from the clock now.
fn expiry_for(args: &Arguments, name: &str) -> Result<SystemTime, CommandError> {
    let usage = CommandError::Usage("an expiry takes <hours>h or <days>d");
    let text = args.required(name)?;
    let (count, unit) = match (text.strip_suffix('h'), text.strip_suffix('d')) {
        (Some(count), _) => (count, 3_600),
        (_, Some(count)) => (count, 86_400),
        _ => return Err(usage),
    };
    let seconds = count.parse::<u64>().ok().and_then(|count| count.checked_mul(unit)).ok_or(usage)?;
    Ok(SystemTime::now() + Duration::from_secs(seconds))
}

/// The signer program, with its standard error passed to the terminal's.
fn signer_for(args: &Arguments) -> Result<SignerProgram, CommandError> {
    let program = args.one("--signer")?.map_or_else(SignerProgram::default, SignerProgram::new);
    Ok(program.with_output(|line| {
        let _ = writeln!(std::io::stderr(), "{line}");
    }))
}

fn write_online(path: &str, file: &[u8]) -> Result<(), CommandError> {
    write_ceremony_file(Path::new(path), file)?;
    let header = header_of(file)?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{path}: {} version {}, expires {}", header.kind, header.version, header.expires)
        .map_err(CommandError::Status)
}

fn rebuild_for(args: &Arguments) -> Result<Rebuild, CommandError> {
    let rebuilt = args.all("--rebuilt");
    if args.not_reproducible {
        if !rebuilt.is_empty() {
            return Err(CommandError::Usage("--rebuilt and --not-reproducible exclude each other"));
        }
        return Ok(Rebuild::NotReproducible);
    }
    let mut artifacts = BTreeMap::new();
    for pair in rebuilt {
        let (path, file) = pair.split_once('=').ok_or(CommandError::Usage("--rebuilt takes <target path>=<file>"))?;
        artifacts.insert(path.to_owned(), read_ceremony_file(Path::new(file))?);
    }
    Ok(Rebuild::Rebuilt(artifacts))
}

/// Writes how each threshold stands, and each delegation; true when all are met.
fn write_status(standings: &[Standing], delegations: &[DelegatedRole]) -> Result<bool, CommandError> {
    let mut stdout = std::io::stdout().lock();
    for standing in standings {
        let state = if standing.met() {
            "met".to_owned()
        } else {
            format!("missing {}", standing.missing().collect::<Vec<_>>().join(", "))
        };
        let (label, counted, threshold) = (&standing.label, standing.counted, standing.threshold);
        writeln!(stdout, "{label}: {counted} of {threshold} signatories count; {state}").map_err(CommandError::Status)?;
    }
    for role in delegations {
        let mut covers = Vec::new();
        if let Some(paths) = &role.paths {
            covers.push(format!("paths {}", paths.join(", ")));
        }
        if let Some(prefixes) = &role.path_hash_prefixes {
            covers.push(format!("path hash prefixes {}", prefixes.join(", ")));
        }
        let (name, covers, keys) = (&role.name, covers.join("; "), role.keyids.join(", "));
        writeln!(stdout, "delegates {name}: {covers}; keys {keys}; threshold {}", role.threshold)
            .map_err(CommandError::Status)?;
    }
    Ok(standings.iter().all(Standing::met))
}

/// Writes one file's status under a line naming it.
fn write_file_status(path: &Path, requirement: &Requirement, file: &[u8]) -> Result<bool, CommandError> {
    writeln!(std::io::stdout().lock(), "{}:", path.display()).map_err(CommandError::Status)?;
    write_status(&requirement.standing(file)?, &requirement.delegations(file)?)
}

fn exit_for(met: bool) -> ExitCode {
    if met {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

<<cli-release>>

fn run_ceremony_command(args: &Arguments) -> Result<ExitCode, CommandError> {
    let words: Vec<&str> = args.positional.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["stage", body, staged] => {
            let file = stage(&read_ceremony_file(Path::new(body))?, args.one("--role")?, SystemTime::now())?;
            write_ceremony_file(Path::new(staged), &file)?;
            Ok(ExitCode::SUCCESS)
        }
        ["status", staged] => {
            let path = Path::new(staged);
            let staged = read_ceremony_file(path)?;
            let requirement = requirements_for(&[path], std::slice::from_ref(&staged), args)?.remove(0);
            write_status(&requirement.standing(&staged)?, &requirement.delegations(&staged)?).map(exit_for)
        }
        ["sign", staged_paths @ ..] if !staged_paths.is_empty() => {
            let paths: Vec<&Path> = staged_paths.iter().map(Path::new).collect();
            let files = paths.iter().map(|path| read_ceremony_file(path)).collect::<Result<Vec<_>, _>>()?;
            let requirements = requirements_for(&paths, &files, args)?;
            let rebuild = rebuild_for(args)?;
            let signer = signer_for(args)?;
            let key = Path::new(args.required("--key")?);
            let staged: Vec<Staged<'_>> = files
                .iter()
                .zip(&requirements)
                .map(|(file, requirement)| Staged { file, requirement, rebuild: &rebuild })
                .collect();
            let signed = sign(&staged, &signer, key)?;
            for (path, file) in paths.iter().zip(&signed) {
                write_ceremony_file(path, file)?;
            }
            for ((path, requirement), file) in paths.iter().zip(&requirements).zip(&signed) {
                write_file_status(path, requirement, file)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        ["release", staged] => run_release(Path::new(staged), args),
        ["snapshot", out] => {
            let root = read_ceremony_file(Path::new(args.required("--trusted")?))?;
            let previous = optional_file(args, "--previous")?;
            let targets = targets_files(args)?;
            if targets.is_empty() {
                return Err(CommandError::Usage("snapshot takes at least one --targets <role>.json"));
            }
            let (expires, signer, key) = (expiry_for(args, "--expires-in")?, signer_for(args)?, args.required("--key")?);
            let file = sign_snapshot(&root, previous.as_deref(), &targets, expires, &signer, Path::new(key))?;
            write_online(out, &file).map(|()| ExitCode::SUCCESS)
        }
        ["timestamp", out] => {
            let root = read_ceremony_file(Path::new(args.required("--trusted")?))?;
            let previous = optional_file(args, "--previous")?;
            let snapshot = read_ceremony_file(Path::new(args.required("--snapshot")?))?;
            let (expires, signer, key) = (expiry_for(args, "--expires-in")?, signer_for(args)?, args.required("--key")?);
            let file = sign_timestamp(&root, previous.as_deref(), &snapshot, expires, &signer, Path::new(key))?;
            write_online(out, &file).map(|()| ExitCode::SUCCESS)
        }
        _ => Err(CommandError::Usage("unknown command")),
    }
}
```

`release` reads the staged targets file, the root, the delegating file
for an audience, the other targets files the snapshot lists, and the
previous snapshot and timestamp where they exist. It writes the three
signed files, the targets file's status, and one line for each online
file.

<a name="chunk-cli-release"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#cli-release`</sub>

```rust {#cli-release}
fn run_release(path: &Path, args: &Arguments) -> Result<ExitCode, CommandError> {
    let staged = read_ceremony_file(path)?;
    let root = read_ceremony_file(Path::new(args.required("--trusted")?))?;
    let role = role_of(path, "targets", args)?;
    let delegator = optional_file(args, "--delegator")?;
    match (role.as_str(), &delegator) {
        ("targets", Some(_)) => return Err(CommandError::Usage("the top-level targets file takes no --delegator")),
        ("targets", None) | (_, Some(_)) => {}
        (_, None) => return Err(CommandError::Usage("a delegated role's file takes --delegator <targets.json>")),
    }
    let (snapshot_path, timestamp_path) = (args.required("--snapshot")?, args.required("--timestamp")?);
    let previous_snapshot = read_if_present(Path::new(snapshot_path))?;
    let previous_timestamp = read_if_present(Path::new(timestamp_path))?;
    let (listed, rebuild, signer) = (targets_files(args)?, rebuild_for(args)?, signer_for(args)?);
    let release = Release {
        root: &root,
        role: &role,
        staged: &staged,
        delegator: delegator.as_deref(),
        rebuild: &rebuild,
        listed: &listed,
        previous_snapshot: previous_snapshot.as_deref(),
        previous_timestamp: previous_timestamp.as_deref(),
        snapshot_expires: expiry_for(args, "--snapshot-expires-in")?,
        timestamp_expires: expiry_for(args, "--timestamp-expires-in")?,
    };
    let signed = sign_release(&release, &signer, Path::new(args.required("--key")?))?;
    write_ceremony_file(path, &signed.targets)?;
    let requirement = requirements_for(&[path], std::slice::from_ref(&signed.targets), args)?.remove(0);
    write_file_status(path, &requirement, &signed.targets)?;
    write_online(snapshot_path, &signed.snapshot)?;
    write_online(timestamp_path, &signed.timestamp)?;
    Ok(ExitCode::SUCCESS)
}
```

## What the tests prove

The ceremony tests run the program as a maintainer runs it, in a scratch
directory, with a stub signer program. The stub is a shell script that
records each call and its standard input, then answers with a signature
the test made in advance with the key the call names. Ed25519 SSHSIG
signatures are deterministic, so the prepared signature is the one
`ssh-keygen` would write. The stub is a shell script, so the tests run on
Unix only.

| Test | Section | Claim |
|---|---|---|
| `a_root_signed_one_signatory_at_a_time_shows_who_is_missing_until_both_thresholds_meet` | §5 | A staged root collects one signature per call, the status names who is missing under each threshold until both are met, and the result is a root a reader walks to. |
| `the_sign_command_signs_only_through_the_signer_program_it_is_given` | §7 | `sign` calls the given program once, with `-Y sign -n release-metadata -f <key>` and the staged body's canonical bytes, adds what it returns, and changes nothing when the program fails. |
| `a_public_delegation_waits_for_every_signatory_the_role_lists` | §8 | The status of a delegation staged for an audience the root marks public counts every signatory its role lists, not its threshold. |
| `staging_an_audience_version_that_delegates_for_more_than_a_day_is_refused` | §8 | `stage` refuses an audience's version that delegates and expires more than 24 hours after it is staged, and one that does not name its role; it stages one that expires within a day, and a top-level targets version whatever its expiry. |
| `the_status_shows_each_delegations_patterns_and_key_ids` | §8 | The status of a staged version that delegates shows each delegation's patterns and key ids, so the signers review what they grant. |
| `the_online_roles_are_signed_by_one_call_each` | §6 | `sign_snapshot` and `sign_timestamp` sign a snapshot and a timestamp that verify, and a refresh over the same snapshot is version 2 and verifies after version 1. |
| `a_stale_or_rewound_online_file_is_refused` | §6 | A timestamp signed with an expiry in the past is refused as expired, and one rewound to version 1 after version 2 as a rollback. |
| `a_signer_programs_lines_reach_the_sink_before_it_returns` | §7 | Each line the signer program writes to its standard error reaches the embedder's sink while the program still runs, and a failure keeps the text. |
| `a_signer_without_a_sink_prints_nothing` | §7 | With no sink, the signer program's standard error prints nowhere: a scheduled job stays quiet. |
| `a_failed_signer_program_reports_what_it_wrote` | §7 | A signer program that fails has its error output in the error, and a signer that succeeds prints nothing. |
| `a_first_root_is_signed_one_signatory_at_a_time` | §5 | A first root is staged and signed one signatory after another; its status says 1 of 2 until the second signs, then met, and readers start from the result. |
| `a_targets_entry_that_differs_from_the_signers_rebuild_is_not_signed` | §6 | `sign` refuses a targets file whose entry differs from the signer's rebuild, naming both hashes, and refuses one with no rebuild; the signer program is not called; the matching rebuild is signed. |
| `a_root_and_its_targets_file_are_signed_with_one_call` | §3, §5 | `sign` given a root and a targets file calls the signer program once, under `release-metadata-batch`, with the batch statement that lists both; each file carries the one signature and the statement; the status is shown per file; a reader reads the targets file under the signed root. |
| `a_release_is_signed_with_one_call_and_lists_its_files_by_version` | §3, §6 | `sign_release` signs a targets file, its snapshot and its timestamp with one call; the snapshot lists the targets file by version only and the timestamp the snapshot; the release verifies; another file of the same version carrying the release's signature is refused, its fault naming the body's hash. |
| `a_batch_signer_that_one_files_thresholds_do_not_list_is_refused` | §3 | `sign_ceremony` refuses a key that the root's thresholds list and the targets role does not, naming `targets`, and signs both files when the key is listed for both. |
| `the_release_command_signs_three_files_with_one_call_to_ssh_keygen` | §3, §6, §7 | The `release` command signs an audience's file, the snapshot and the timestamp through `ssh-keygen` itself, with one call, and the three verify. |

<a name="chunk-ceremony-tests"></a><sub>[`tests/conformance/ceremony.rs`](../../crates/x0k-release-metadata/tests/conformance/ceremony.rs) · `#ceremony-tests` · assembles [ceremony-keys](#chunk-ceremony-keys) · [ceremony-scratch](#chunk-ceremony-scratch) · [ceremony-bodies](#chunk-ceremony-bodies) · [ceremony-cases](#chunk-ceremony-cases) · [ceremony-batch-cases](#chunk-ceremony-batch-cases)</sub>

```rust {#ceremony-tests file="tests/conformance/ceremony.rs"}
//! Decision §5, §6 and §7: the ceremony commands, run as a maintainer runs them.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};
use ssh_encoding::Encode;
use ssh_key::private::Ed25519Keypair;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use x0k_release_metadata::{
    canonical_json, key_id, parse_utc, sign_ceremony, sign_release, sign_snapshot, sign_timestamp, stage, verify,
    Artifact, CeremonyError, Fetched, Rebuild, Refusal, Release, SignatureFault, Signer, SignerError, SignerProgram,
    TrustedState, Verified, BATCH_NAMESPACE, NAMESPACE,
};

const PROGRAM: &str = env!("CARGO_BIN_EXE_x0k-release-metadata");
const NOW: &str = "2026-11-05T00:00:00Z";
const LATER: &str = "2030-01-01T00:00:00Z";
const ARTIFACT: &[u8] = b"chariot 1.0\n";
const PATH: &str = "fleet/chariot-1.0.tar";

<<ceremony-keys>>

<<ceremony-scratch>>

<<ceremony-bodies>>

<<ceremony-cases>>

<<ceremony-batch-cases>>
```

A signatory's key is an SSH key, as `ssh-keygen` holds it; the online key
is a TUF `ed25519` key, since a person never signs with it.

<a name="chunk-ceremony-keys"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#ceremony-keys`</sub>

```rust {#ceremony-keys}
/// A signatory's SSH key: its key object, its id, and the private half the test signs with.
struct SignatoryKey {
    name: &'static str,
    id: String,
    object: Value,
    private: PrivateKey,
}

impl SignatoryKey {
    fn new(seed: u8, name: &'static str) -> Self {
        let pair = Ed25519Keypair::from_seed(&[seed; 32]);
        let line = PublicKey::from(KeyData::Ed25519(pair.public)).to_openssh().expect("key line");
        let object = json!({
            "keytype": "ssh-ed25519", "scheme": "sshsig-ssh-ed25519", "keyval": { "public": line },
            "x-release-metadata-signatory": name, "x-release-metadata-custody": "software",
        });
        Self { name, id: key_id(&object).expect("key id"), object, private: PrivateKey::from(pair) }
    }

    fn sshsig(&self, message: &[u8]) -> SshSig {
        self.sshsig_under(NAMESPACE, message)
    }

    fn sshsig_under(&self, namespace: &str, message: &[u8]) -> SshSig {
        self.private.sign(namespace, HashAlg::Sha512, message).expect("sshsig")
    }

    fn signature(&self, message: &[u8]) -> Value {
        let mut blob = Vec::new();
        self.sshsig(message).encode(&mut blob).expect("sshsig encoding");
        json!({ "keyid": self.id, "sig": hex::encode(blob) })
    }
}

/// The online key that signs the snapshot and the timestamp.
struct OnlineKey {
    id: String,
    object: Value,
    key: SigningKey,
}

impl OnlineKey {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[10; 32]);
        let object = json!({
            "keytype": "ed25519", "scheme": "ed25519",
            "keyval": { "public": hex::encode(key.verifying_key().as_bytes()) },
        });
        Self { id: key_id(&object).expect("key id"), object, key }
    }

    fn signature(&self, message: &[u8]) -> Value {
        json!({ "keyid": self.id, "sig": hex::encode(self.key.sign(message).to_bytes()) })
    }
}
```

The scratch directory holds the files, the stub signer and its record.
The stub reads the key path it is given and answers with
`<key path>.sig`, which the test writes for each key it expects.

<a name="chunk-ceremony-scratch"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#ceremony-scratch`</sub>

```rust {#ceremony-scratch}
struct Scratch {
    dir: tempfile::TempDir,
}

impl Scratch {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().expect("scratch directory") }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn put(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, serde_json::to_vec_pretty(value).expect("json")).expect("write");
        path
    }

    /// Writes the stub signer, ready to answer for `keys` over `message`.
    fn stub_signer(&self, keys: &[&SignatoryKey], message: &[u8]) -> PathBuf {
        for key in keys {
            let pem = key.sshsig(message).to_pem(LineEnding::LF).expect("armor");
            fs::write(self.path(&format!("{}.sig", key.name)), pem).expect("prepared signature");
        }
        let dir = self.dir.path().display();
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{dir}/calls'\n\
             echo 'Signing data on standard input' >&2\n\
             cat > '{dir}/message'\n\
             cat \"$6.sig\"\n"
        );
        let path = self.path("signer");
        fs::write(&path, script).expect("stub signer");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable");
        path
    }

    /// Prepares the stub's answer for `key` as a batch signature over `message`.
    fn prepare_batch(&self, key: &SignatoryKey, message: &[u8]) {
        let pem = key.sshsig_under(BATCH_NAMESPACE, message).to_pem(LineEnding::LF).expect("armor");
        fs::write(self.path(&format!("{}.sig", key.name)), pem).expect("prepared signature");
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("calls")).map(|text| text.lines().map(str::to_owned).collect()).unwrap_or_default()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(PROGRAM).args(args).output().expect("x0k-release-metadata runs")
    }
}

fn text(path: &std::path::Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
```

<a name="chunk-ceremony-bodies"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#ceremony-bodies`</sub>

```rust {#ceremony-bodies}
fn message(body: &Value) -> Vec<u8> {
    canonical_json(body).expect("canonical body")
}

fn envelope(body: &Value, signatures: Vec<Value>) -> Value {
    json!({ "signed": body, "signatures": signatures })
}

fn listing(keys: &[&Value], ids: &[&str]) -> Map<String, Value> {
    ids.iter().zip(keys).map(|(id, key)| ((*id).to_owned(), (*key).clone())).collect()
}

/// A root whose root role is `root_keys` at a threshold of two, whose targets
/// role is Alice's key, and whose snapshot and timestamp roles are the online key.
fn root_body(version: u64, root_keys: &[&SignatoryKey], alice: &SignatoryKey, online: &OnlineKey) -> Value {
    let mut keys: Map<String, Value> = root_keys.iter().map(|k| (k.id.clone(), k.object.clone())).collect();
    keys.insert(alice.id.clone(), alice.object.clone());
    keys.insert(online.id.clone(), online.object.clone());
    let root_ids: Vec<&str> = root_keys.iter().map(|k| k.id.as_str()).collect();
    json!({
        "_type": "root", "spec_version": "1.0.37", "consistent_snapshot": false,
        "version": version, "expires": LATER, "keys": keys,
        "roles": {
            "root": { "keyids": root_ids, "threshold": 2 },
            "timestamp": { "keyids": [online.id], "threshold": 1 },
            "snapshot": { "keyids": [online.id], "threshold": 1 },
            "targets": { "keyids": [alice.id], "threshold": 1 },
        },
    })
}

fn targets_body(entries: &[&str], delegations: Option<Value>) -> Value {
    let entry = json!({
        "length": ARTIFACT.len(),
        "hashes": {
            "sha256": hex::encode(Sha256::digest(ARTIFACT)),
            "sha512": hex::encode(Sha512::digest(ARTIFACT)),
        },
    });
    let targets: Map<String, Value> = entries.iter().map(|p| ((*p).to_owned(), entry.clone())).collect();
    let mut body = json!({ "_type": "targets", "spec_version": "1.0.37", "version": 1, "expires": LATER, "targets": targets });
    if let Some(delegations) = delegations {
        body["delegations"] = delegations;
    }
    body
}

/// A reader that trusts `trusted_root` updates to `new_root` and looks up the artifact.
fn reader_update(trusted_root: Vec<u8>, new_roots: Vec<Vec<u8>>, alice: &SignatoryKey, online: &OnlineKey) -> Result<Verified, Refusal> {
    let bytes = |value: &Value| serde_json::to_vec(value).expect("json");
    let targets = targets_body(&[PATH], None);
    let targets = bytes(&envelope(&targets, vec![alice.signature(&message(&targets))]));
    let snapshot = json!({
        "_type": "snapshot", "spec_version": "1.0.37", "version": 1, "expires": LATER,
        "meta": { "targets.json": { "version": 1 } },
    });
    let snapshot = bytes(&envelope(&snapshot, vec![online.signature(&message(&snapshot))]));
    let timestamp = json!({
        "_type": "timestamp", "spec_version": "1.0.37", "version": 1, "expires": LATER,
        "meta": { "snapshot.json": { "version": 1 } },
    });
    let timestamp = bytes(&envelope(&timestamp, vec![online.signature(&message(&timestamp))]));
    let fetched = Fetched {
        roots: new_roots,
        timestamp,
        snapshot,
        targets: BTreeMap::from([("targets".to_owned(), targets)]),
    };
    let hashes = BTreeMap::from([("sha256".to_owned(), hex::encode(Sha256::digest(ARTIFACT)))]);
    let artifact = Artifact { length: ARTIFACT.len() as u64, hashes };
    verify(&TrustedState::from_root(trusted_root), &fetched, PATH, &artifact, parse_utc(NOW).expect("now"))
}

/// Writes `time` in TUF's date-time form, `YYYY-MM-DDTHH:MM:SSZ`.
fn tuf_time(time: SystemTime) -> String {
    let seconds = i64::try_from(time.duration_since(UNIX_EPOCH).expect("after 1970").as_secs()).expect("seconds");
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let (hour, minute, second) = (rest / 3600, rest % 3600 / 60, rest % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The time `hours` from now, as TUF writes it.
fn hours_from_now(hours: u64) -> String {
    tuf_time(SystemTime::now() + Duration::from_secs(hours * 3600))
}

/// A fleet version that delegates chariot 1.1's files to a session key, expiring at `expires`.
fn advance_version(session: &SignatoryKey, expires: &str) -> Value {
    let advance = json!({
        "keys": listing(&[&session.object], &[session.id.as_str()]),
        "roles": [{ "name": "chariot-1.1", "keyids": [session.id], "threshold": 1, "terminating": true, "paths": ["fleet/chariot-1.1-*"] }],
    });
    let mut body = targets_body(&[], Some(advance));
    body["expires"] = json!(expires);
    body
}
```

The root ceremony rotates chariot's root keys: version 1 lists root-1
and root-2, version 2 lists root-2 and root-3, each at a threshold of two.
root-3 and root-2 sign first, which meets version 2's threshold and not
version 1's; the status must still name root-1.

<a name="chunk-ceremony-cases"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#ceremony-cases`</sub>

```rust {#ceremony-cases}
/// The rotation of root version 1 to 2, staged and ready to sign.
struct RootCeremony {
    scratch: Scratch,
    keys: [SignatoryKey; 3],
    alice: SignatoryKey,
    online: OnlineKey,
    next: Value,
    trusted: PathBuf,
    staged: PathBuf,
    signer: PathBuf,
}

impl RootCeremony {
    fn new() -> Self {
        let scratch = Scratch::new();
        let keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2"), SignatoryKey::new(3, "root-3")];
        let alice = SignatoryKey::new(20, "alice");
        let online = OnlineKey::new();
        let first = root_body(1, &[&keys[0], &keys[1]], &alice, &online);
        let signatures = vec![keys[0].signature(&message(&first)), keys[1].signature(&message(&first))];
        let trusted = scratch.put("1.root.json", &envelope(&first, signatures));
        let next = root_body(2, &[&keys[1], &keys[2]], &alice, &online);
        let body = scratch.put("2.root.body.json", &next);
        let staged = scratch.path("2.root.json");
        let signer = scratch.stub_signer(&[&keys[0], &keys[1], &keys[2]], &message(&next));
        let staging = scratch.run(&["stage", &text(&body), &text(&staged)]);
        assert!(staging.status.success(), "stage: {}", stderr(&staging));
        Self { scratch, keys, alice, online, next, trusted, staged, signer }
    }

    fn sign(&self, key: &str) -> Output {
        let key = text(&self.scratch.path(key));
        let (staged, trusted, signer) = (text(&self.staged), text(&self.trusted), text(&self.signer));
        self.scratch.run(&["sign", &staged, "--trusted", &trusted, "--key", &key, "--signer", &signer])
    }

    fn status(&self) -> Output {
        self.scratch.run(&["status", &text(&self.staged), "--trusted", &text(&self.trusted)])
    }
}

#[test]
fn a_root_signed_one_signatory_at_a_time_shows_who_is_missing_until_both_thresholds_meet() {
    let ceremony = RootCeremony::new();
    let staged = ceremony.status();
    assert_eq!(staged.status.code(), Some(1), "{}", stderr(&staged));
    assert!(stdout(&staged).contains("root version 1: 0 of 2 signatories count; missing root-1, root-2"), "{}", stdout(&staged));
    assert!(stdout(&staged).contains("root version 2: 0 of 2 signatories count; missing root-2, root-3"), "{}", stdout(&staged));

    for key in ["root-3", "root-2"] {
        let signed = ceremony.sign(key);
        assert!(signed.status.success(), "sign {key}: {}", stderr(&signed));
    }
    let partly = ceremony.status();
    assert_eq!(partly.status.code(), Some(1), "{}", stdout(&partly));
    assert!(stdout(&partly).contains("root version 1: 1 of 2 signatories count; missing root-1"), "{}", stdout(&partly));
    assert!(stdout(&partly).contains("root version 2: 2 of 2 signatories count; met"), "{}", stdout(&partly));

    let last = ceremony.sign("root-1");
    assert!(last.status.success(), "sign root-1: {}", stderr(&last));
    let done = ceremony.status();
    assert_eq!(done.status.code(), Some(0), "{}", stdout(&done));

    let trusted = fs::read(&ceremony.trusted).expect("root 1");
    let signed = fs::read(&ceremony.staged).expect("root 2");
    let verified = reader_update(trusted, vec![signed.clone()], &ceremony.alice, &ceremony.online).expect("a reader walks to root 2");
    assert_eq!(verified.trusted.root, signed);
}

#[test]
fn the_sign_command_signs_only_through_the_signer_program_it_is_given() {
    let ceremony = RootCeremony::new();
    let signed = ceremony.sign("root-2");
    assert!(signed.status.success(), "{}", stderr(&signed));
    assert!(stderr(&signed).contains("Signing data on standard input"), "the signer program's own output reaches the terminal: {}", stderr(&signed));
    let key = text(&ceremony.scratch.path("root-2"));
    assert_eq!(ceremony.scratch.calls(), vec![format!("-Y sign -n release-metadata -f {key}")]);
    assert_eq!(fs::read(ceremony.scratch.path("message")).expect("recorded message"), message(&ceremony.next));
    let file: Value = serde_json::from_slice(&fs::read(&ceremony.staged).expect("staged")).expect("json");
    let added = ceremony.keys[1].signature(&message(&ceremony.next));
    assert_eq!(file["signatures"], json!([added]));

    let before = fs::read(&ceremony.staged).expect("staged");
    let failed = ceremony.sign("nobody");
    assert_eq!(failed.status.code(), Some(2), "{}", stdout(&failed));
    assert!(stderr(&failed).contains("Signing data on standard input"), "a failed signer's output is shown: {}", stderr(&failed));
    assert_eq!(ceremony.scratch.calls().len(), 2);
    assert_eq!(fs::read(&ceremony.staged).expect("staged"), before);
}

#[test]
fn a_targets_entry_that_differs_from_the_signers_rebuild_is_not_signed() {
    let scratch = Scratch::new();
    let root_keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
    let alice = SignatoryKey::new(20, "alice");
    let online = OnlineKey::new();
    let root = root_body(1, &[&root_keys[0], &root_keys[1]], &alice, &online);
    let trusted = scratch.put("root.json", &envelope(&root, Vec::new()));
    let delegations = json!({
        "keys": listing(&[&alice.object], &[alice.id.as_str()]),
        "roles": [{ "name": "fleet", "keyids": [alice.id], "threshold": 1, "terminating": true, "paths": ["fleet/*"] }],
    });
    let delegator = scratch.put("targets.json", &envelope(&targets_body(&[], Some(delegations)), Vec::new()));
    let fleet = targets_body(&[PATH], None);
    let body = scratch.put("fleet.body.json", &fleet);
    let staged = scratch.path("fleet.json");
    assert!(scratch.run(&["stage", &text(&body), &text(&staged)]).status.success());
    let signer = scratch.stub_signer(&[&alice], &message(&fleet));
    let tampered = b"chariot 6.6\n";
    fs::write(scratch.path("tampered.tar"), tampered).expect("tampered rebuild");
    fs::write(scratch.path("rebuilt.tar"), ARTIFACT).expect("rebuild");
    let (staged_text, key) = (text(&staged), text(&scratch.path("alice")));
    let (trusted, delegator, signer) = (text(&trusted), text(&delegator), text(&signer));
    let sign = |rebuild: &[&str]| {
        let mut args = vec!["sign", &staged_text, "--trusted", &trusted, "--delegator", &delegator];
        args.extend(["--role", "fleet", "--key", &key, "--signer", &signer]);
        args.extend(rebuild);
        scratch.run(&args)
    };
    let before = fs::read(&staged).expect("staged");

    let tampered_rebuild = format!("{PATH}={}", text(&scratch.path("tampered.tar")));
    let refused = sign(&["--rebuilt", &tampered_rebuild]);
    assert_eq!(refused.status.code(), Some(2), "{}", stdout(&refused));
    assert!(stderr(&refused).contains(&hex::encode(Sha256::digest(ARTIFACT))), "{}", stderr(&refused));
    assert!(stderr(&refused).contains(&hex::encode(Sha256::digest(tampered))), "{}", stderr(&refused));

    let unrebuilt = sign(&[]);
    assert_eq!(unrebuilt.status.code(), Some(2), "{}", stdout(&unrebuilt));
    assert!(stderr(&unrebuilt).contains("has no rebuild"), "{}", stderr(&unrebuilt));
    assert!(scratch.calls().is_empty(), "the signer program ran: {:?}", scratch.calls());
    assert_eq!(fs::read(&staged).expect("staged"), before);

    let rebuild = format!("{PATH}={}", text(&scratch.path("rebuilt.tar")));
    let signed = sign(&["--rebuilt", &rebuild]);
    assert!(signed.status.success(), "{}", stderr(&signed));
    assert_eq!(scratch.calls().len(), 1);
    assert!(stdout(&signed).contains("fleet: 1 of 1 signatories count; met"), "{}", stdout(&signed));
}

#[test]
fn a_public_delegation_waits_for_every_signatory_the_role_lists() {
    let scratch = Scratch::new();
    let root_keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
    let (alice, bob) = (SignatoryKey::new(20, "alice"), SignatoryKey::new(21, "bob"));
    let session = SignatoryKey::new(40, "session");
    let online = OnlineKey::new();
    let mut root = root_body(1, &[&root_keys[0], &root_keys[1]], &alice, &online);
    root["x-release-metadata-public-audiences"] = json!(["public"]);
    let trusted = scratch.put("root.json", &envelope(&root, Vec::new()));
    let audiences = json!({
        "keys": listing(&[&alice.object, &bob.object], &[alice.id.as_str(), bob.id.as_str()]),
        "roles": [{ "name": "public", "keyids": [alice.id, bob.id], "threshold": 1, "terminating": true, "paths": ["public/*"] }],
    });
    let delegator = scratch.put("targets.json", &envelope(&targets_body(&[], Some(audiences)), Vec::new()));
    let advance = json!({
        "keys": listing(&[&session.object], &[session.id.as_str()]),
        "roles": [{ "name": "chariot-1.1", "keyids": [session.id], "threshold": 1, "terminating": true, "paths": ["public/chariot-1.1-*"] }],
    });
    let mut public = targets_body(&[], Some(advance));
    public["expires"] = json!(hours_from_now(12));
    let body = scratch.put("public.body.json", &public);
    let staged = scratch.path("public.json");
    let staging = scratch.run(&["stage", &text(&body), &text(&staged), "--role", "public"]);
    assert!(staging.status.success(), "{}", stderr(&staging));
    let signer = scratch.stub_signer(&[&alice, &bob], &message(&public));
    let (staged, trusted, delegator, signer) = (text(&staged), text(&trusted), text(&delegator), text(&signer));
    let sign = |key: &str| {
        let key = text(&scratch.path(key));
        let mut args = vec!["sign", staged.as_str(), "--trusted", trusted.as_str(), "--delegator", delegator.as_str()];
        args.extend(["--role", "public", "--key", key.as_str(), "--signer", signer.as_str()]);
        scratch.run(&args)
    };

    let first = sign("alice");
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(stdout(&first).contains("public: 1 of 2 signatories count; missing bob"), "{}", stdout(&first));
    let second = sign("bob");
    assert!(second.status.success(), "{}", stderr(&second));
    assert!(stdout(&second).contains("public: 2 of 2 signatories count; met"), "{}", stdout(&second));
}

#[test]
fn staging_an_audience_version_that_delegates_for_more_than_a_day_is_refused() {
    let scratch = Scratch::new();
    let session = SignatoryKey::new(40, "session");
    let stage = |name: &str, body: &Value, role: Option<&str>| {
        let body = text(&scratch.put(&format!("{name}.body.json"), body));
        let staged = text(&scratch.path(&format!("{name}.json")));
        let mut args = vec!["stage", body.as_str(), staged.as_str()];
        args.extend(role.map(|role| ["--role", role]).into_iter().flatten());
        scratch.run(&args)
    };

    let a_day_and_an_hour = stage("fleet-25h", &advance_version(&session, &hours_from_now(25)), Some("fleet"));
    assert_eq!(a_day_and_an_hour.status.code(), Some(2), "{}", stdout(&a_day_and_an_hour));
    assert!(stderr(&a_day_and_an_hour).contains("more than 24 hours"), "{}", stderr(&a_day_and_an_hour));
    let within_a_day = stage("fleet-23h", &advance_version(&session, &hours_from_now(23)), Some("fleet"));
    assert!(within_a_day.status.success(), "{}", stderr(&within_a_day));
    let unnamed = stage("fleet-unnamed", &advance_version(&session, &hours_from_now(23)), None);
    assert_eq!(unnamed.status.code(), Some(2), "{}", stdout(&unnamed));
    let top_level = stage("targets", &advance_version(&session, LATER), Some("targets"));
    assert!(top_level.status.success(), "{}", stderr(&top_level));
}

#[test]
fn the_status_shows_each_delegations_patterns_and_key_ids() {
    let scratch = Scratch::new();
    let root_keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
    let alice = SignatoryKey::new(20, "alice");
    let session = SignatoryKey::new(40, "session");
    let online = OnlineKey::new();
    let root = root_body(1, &[&root_keys[0], &root_keys[1]], &alice, &online);
    let trusted = text(&scratch.put("root.json", &envelope(&root, Vec::new())));
    let audiences = json!({
        "keys": listing(&[&alice.object], &[alice.id.as_str()]),
        "roles": [{ "name": "fleet", "keyids": [alice.id], "threshold": 1, "terminating": true, "paths": ["fleet/*"] }],
    });
    let delegator = text(&scratch.put("targets.json", &envelope(&targets_body(&[], Some(audiences)), Vec::new())));
    let body = text(&scratch.put("fleet.body.json", &advance_version(&session, &hours_from_now(12))));
    let staged = text(&scratch.path("fleet.json"));
    let staging = scratch.run(&["stage", &body, &staged, "--role", "fleet"]);
    assert!(staging.status.success(), "{}", stderr(&staging));

    let status = scratch.run(&["status", &staged, "--trusted", &trusted, "--delegator", &delegator, "--role", "fleet"]);
    assert_eq!(status.status.code(), Some(1), "{}", stderr(&status));
    let line = format!("delegates chariot-1.1: paths fleet/chariot-1.1-*; keys {}; threshold 1", session.id);
    assert!(stdout(&status).contains(&line), "{}", stdout(&status));
}

#[test]
fn a_first_root_is_signed_one_signatory_at_a_time() {
    let scratch = Scratch::new();
    let keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
    let alice = SignatoryKey::new(20, "alice");
    let online = OnlineKey::new();
    let first = root_body(1, &[&keys[0], &keys[1]], &alice, &online);
    let body = text(&scratch.put("1.root.body.json", &first));
    let staged = text(&scratch.path("1.root.json"));
    let staging = scratch.run(&["stage", &body, &staged]);
    assert!(staging.status.success(), "{}", stderr(&staging));
    let signer = text(&scratch.stub_signer(&[&keys[0], &keys[1]], &message(&first)));
    let status = || scratch.run(&["status", &staged]);
    let sign = |key: &str| scratch.run(&["sign", &staged, "--key", &text(&scratch.path(key)), "--signer", &signer]);

    let unsigned = status();
    assert_eq!(unsigned.status.code(), Some(1), "{}", stderr(&unsigned));
    assert!(stdout(&unsigned).contains("root version 1: 0 of 2 signatories count; missing root-1, root-2"), "{}", stdout(&unsigned));
    let one = sign("root-1");
    assert!(one.status.success(), "{}", stderr(&one));
    let half = status();
    assert_eq!(half.status.code(), Some(1), "one of two signatories is not the threshold: {}", stdout(&half));
    assert!(stdout(&half).contains("root version 1: 1 of 2 signatories count; missing root-2"), "{}", stdout(&half));
    let two = sign("root-2");
    assert!(two.status.success(), "{}", stderr(&two));
    let done = status();
    assert_eq!(done.status.code(), Some(0), "{}", stdout(&done));
    assert!(stdout(&done).contains("root version 1: 2 of 2 signatories count; met"), "{}", stdout(&done));

    let root = fs::read(&staged).expect("root 1");
    reader_update(root, Vec::new(), &alice, &online).expect("a reader starts from the signed first root");
}

/// Signs in process with a software SSH key, the way `ssh-keygen -Y sign` does.
struct InProcessSigner<'a>(&'a SignatoryKey);

impl Signer for InProcessSigner<'_> {
    fn sign(&self, _key: &Path, namespace: &str, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let envelope = self.0.private.sign(namespace, HashAlg::Sha512, message).expect("sshsig");
        Ok(envelope.to_pem(LineEnding::LF).expect("armor").into_bytes())
    }
}

/// A root whose snapshot and timestamp roles are the SSH key `online`, with
/// one targets file that Alice signed and that lists the artifact.
struct OnlineRepository {
    root: Vec<u8>,
    targets: Vec<u8>,
    online: SignatoryKey,
}

impl OnlineRepository {
    fn new() -> Self {
        let root_keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
        let alice = SignatoryKey::new(20, "alice");
        let online = SignatoryKey::new(10, "online");
        let mut keys: Map<String, Value> = root_keys.iter().map(|k| (k.id.clone(), k.object.clone())).collect();
        keys.insert(alice.id.clone(), alice.object.clone());
        keys.insert(online.id.clone(), online.object.clone());
        let root_ids: Vec<&str> = root_keys.iter().map(|k| k.id.as_str()).collect();
        let root = json!({
            "_type": "root", "spec_version": "1.0.37", "consistent_snapshot": false,
            "version": 1, "expires": LATER, "keys": keys,
            "roles": {
                "root": { "keyids": root_ids, "threshold": 2 },
                "timestamp": { "keyids": [online.id], "threshold": 1 },
                "snapshot": { "keyids": [online.id], "threshold": 1 },
                "targets": { "keyids": [alice.id], "threshold": 1 },
            },
        });
        let targets = targets_body(&[PATH], None);
        let targets = envelope(&targets, vec![alice.signature(&message(&targets))]);
        let bytes = |value: &Value| serde_json::to_vec(value).expect("json");
        Self { root: bytes(&envelope(&root, Vec::new())), targets: bytes(&targets), online }
    }

    fn targets_files(&self) -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([("targets".to_owned(), self.targets.clone())])
    }

    fn snapshot(&self, previous: Option<&[u8]>, expires: SystemTime) -> Vec<u8> {
        let signer = InProcessSigner(&self.online);
        sign_snapshot(&self.root, previous, &self.targets_files(), expires, &signer, Path::new("online")).expect("snapshot")
    }

    fn timestamp(&self, previous: Option<&[u8]>, snapshot: &[u8], expires: SystemTime) -> Vec<u8> {
        let signer = InProcessSigner(&self.online);
        sign_timestamp(&self.root, previous, snapshot, expires, &signer, Path::new("online")).expect("timestamp")
    }

    fn verify(&self, trusted: &TrustedState, snapshot: &[u8], timestamp: &[u8]) -> Result<Verified, Refusal> {
        let fetched = Fetched {
            roots: Vec::new(),
            timestamp: timestamp.to_vec(),
            snapshot: snapshot.to_vec(),
            targets: self.targets_files(),
        };
        let hashes = BTreeMap::from([("sha256".to_owned(), hex::encode(Sha256::digest(ARTIFACT)))]);
        let artifact = Artifact { length: ARTIFACT.len() as u64, hashes };
        verify(trusted, &fetched, PATH, &artifact, SystemTime::now())
    }
}

fn hours(count: u64) -> Duration {
    Duration::from_secs(count * 3_600)
}

fn version_of(file: &[u8]) -> u64 {
    let value: Value = serde_json::from_slice(file).expect("json");
    value["signed"]["version"].as_u64().expect("version")
}

#[test]
fn the_online_roles_are_signed_by_one_call_each() {
    let repository = OnlineRepository::new();
    let later = SystemTime::now() + hours(24);
    let snapshot = repository.snapshot(None, later);
    let timestamp = repository.timestamp(None, &snapshot, later);
    assert_eq!((version_of(&snapshot), version_of(&timestamp)), (1, 1));
    let first = repository
        .verify(&TrustedState::from_root(repository.root.clone()), &snapshot, &timestamp)
        .expect("the signed snapshot and timestamp verify");

    let refreshed = repository.timestamp(Some(&timestamp), &snapshot, later + hours(12));
    assert_eq!(version_of(&refreshed), 2);
    repository.verify(&first.trusted, &snapshot, &refreshed).expect("the refresh verifies after the first timestamp");
}

#[test]
fn a_stale_or_rewound_online_file_is_refused() {
    let repository = OnlineRepository::new();
    let later = SystemTime::now() + hours(24);
    let snapshot = repository.snapshot(None, later);
    let trusted = TrustedState::from_root(repository.root.clone());

    let stale = repository.timestamp(None, &snapshot, SystemTime::now() - hours(1));
    let refusal = repository.verify(&trusted, &snapshot, &stale).expect_err("an expired timestamp");
    assert_eq!((refusal.role.as_str(), refusal.rule.code()), ("timestamp", "expired"));

    let first = repository.timestamp(None, &snapshot, later);
    let second = repository.timestamp(Some(&first), &snapshot, later);
    let after_second = repository.verify(&trusted, &snapshot, &second).expect("version 2 verifies").trusted;
    let rewound = repository.timestamp(None, &snapshot, later);
    let refusal = repository.verify(&after_second, &snapshot, &rewound).expect_err("a timestamp rewound to version 1");
    assert_eq!((refusal.role.as_str(), refusal.rule.code()), ("timestamp", "rollback"));
}

#[test]
fn a_failed_signer_program_reports_what_it_wrote() {
    let scratch = Scratch::new();
    let program = scratch.path("failing-signer");
    fs::write(&program, "#!/bin/sh\necho 'no such key' >&2\nexit 1\n").expect("failing signer");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("executable");
    let error = SignerProgram::new(&program).sign(Path::new("missing"), NAMESPACE, b"message").expect_err("fails");
    assert!(matches!(&error, SignerError::Failed { stderr, .. } if stderr == "no such key"), "{error:?}");
}

/// Writes an executable shell script into the scratch directory.
fn script(scratch: &Scratch, name: &str, body: &str) -> PathBuf {
    let path = scratch.path(name);
    fs::write(&path, format!("#!/bin/sh\n{body}")).expect("script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable");
    path
}

#[test]
fn a_signer_programs_lines_reach_the_sink_before_it_returns() {
    let scratch = Scratch::new();
    let go = text(&scratch.path("go"));
    // The stub prints its prompt, then waits until the sink has seen it; a
    // line delivered only after the program ended would never let it finish.
    let program = script(
        &scratch,
        "prompting-signer",
        &format!(
            "cat > /dev/null\necho 'Confirm user presence for key ED25519-SK' >&2\n\
             i=0\nwhile [ ! -e '{go}' ]; do i=$((i+1)); [ $i -gt 200 ] && exit 3; sleep 0.05; done\necho signed\n"
        ),
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (sink_seen, sink_go) = (Arc::clone(&seen), go.clone());
    let signer = SignerProgram::new(&program).with_output(move |line| {
        sink_seen.lock().expect("lines").push(line.to_owned());
        if line.starts_with("Confirm user presence") {
            fs::write(&sink_go, b"").expect("go");
        }
    });
    let signature = signer.sign(Path::new("key"), NAMESPACE, b"message").expect("signs once the sink has the prompt");
    assert_eq!(signature, b"signed\n");
    assert_eq!(*seen.lock().expect("lines"), ["Confirm user presence for key ED25519-SK"]);

    let failing = script(&scratch, "failing-signer", "cat > /dev/null\necho 'no such key' >&2\nexit 1\n");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink_lines = Arc::clone(&lines);
    let error = SignerProgram::new(&failing)
        .with_output(move |line| sink_lines.lock().expect("lines").push(line.to_owned()))
        .sign(Path::new("key"), NAMESPACE, b"message")
        .expect_err("fails");
    assert!(matches!(&error, SignerError::Failed { stderr, .. } if stderr == "no such key"), "{error:?}");
    assert_eq!(*lines.lock().expect("lines"), ["no such key"]);
}

#[test]
fn a_signer_without_a_sink_prints_nothing() {
    const CHILD: &str = "X0K_RELEASE_METADATA_QUIET_CHILD";
    if let Some(program) = std::env::var_os(CHILD) {
        // The child run: sign through a stub that writes to its standard
        // error, with no sink, and let the parent read this process's output.
        let signature = SignerProgram::new(program).sign(Path::new("key"), NAMESPACE, b"message").expect("signs");
        assert_eq!(signature, b"signed\n");
        return;
    }
    let scratch = Scratch::new();
    let program = script(&scratch, "chatty-signer", "cat > /dev/null\necho 'Signing data on standard input' >&2\necho signed\n");
    let child = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", "ceremony::a_signer_without_a_sink_prints_nothing", "--nocapture", "--test-threads", "1"])
        .env(CHILD, &program)
        .output()
        .expect("the child run");
    assert!(child.status.success(), "{}", stderr(&child));
    assert!(stdout(&child).contains("1 passed"), "the child ran the signing: {}", stdout(&child));
    assert!(!stderr(&child).contains("Signing data on standard input"), "a quiet signer printed: {}", stderr(&child));
}
```

## Batch signing

The batch tests sign several files with one key and count the calls to
the signer. The statement a batch signature signs is computed here a
second time, from the decision's description of it, so a change to its
format is red here and not only in the vectors.

<a name="chunk-ceremony-batch-cases"></a><sub>[`src/ceremony.rs`](../../crates/x0k-release-metadata/src/ceremony.rs) · `#ceremony-batch-cases`</sub>

```rust {#ceremony-batch-cases}

/// The statement a batch signature over `files` signs: each file's type,
/// role, version and the SHA-256 of its body's canonical bytes.
fn batch_statement(files: &[(&str, &str, &Value)]) -> Value {
    let listed: Vec<Value> = files
        .iter()
        .map(|(kind, role, body)| {
            let sha256 = hex::encode(Sha256::digest(message(body)));
            json!({ "_type": kind, "role": role, "version": body["version"], "hashes": { "sha256": sha256 } })
        })
        .collect();
    json!({ "_type": "release-metadata-batch", "files": listed })
}

fn signed_file(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("signed file")).expect("json")
}

/// A reader that trusts `root` looks up the artifact in `targets`, under a
/// snapshot and a timestamp that the online key signs.
fn read_release(root: Vec<u8>, targets: BTreeMap<String, Vec<u8>>, online: &OnlineKey) -> Result<Verified, Refusal> {
    let bytes = |value: &Value| serde_json::to_vec(value).expect("json");
    let meta: Map<String, Value> = targets.keys().map(|role| (format!("{role}.json"), json!({ "version": 1 }))).collect();
    let snapshot = json!({ "_type": "snapshot", "spec_version": "1.0.37", "version": 1, "expires": LATER, "meta": meta });
    let snapshot = bytes(&envelope(&snapshot, vec![online.signature(&message(&snapshot))]));
    let timestamp = json!({
        "_type": "timestamp", "spec_version": "1.0.37", "version": 1, "expires": LATER,
        "meta": { "snapshot.json": { "version": 1 } },
    });
    let timestamp = bytes(&envelope(&timestamp, vec![online.signature(&message(&timestamp))]));
    let fetched = Fetched { roots: Vec::new(), timestamp, snapshot, targets };
    let hashes = BTreeMap::from([("sha256".to_owned(), hex::encode(Sha256::digest(ARTIFACT)))]);
    let artifact = Artifact { length: ARTIFACT.len() as u64, hashes };
    verify(&TrustedState::from_root(root), &fetched, PATH, &artifact, parse_utc(NOW).expect("now"))
}

#[test]
fn a_root_and_its_targets_file_are_signed_with_one_call() {
    let scratch = Scratch::new();
    let keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
    let online = OnlineKey::new();
    let root = root_body(1, &[&keys[0], &keys[1]], &keys[0], &online);
    let targets = targets_body(&[PATH], None);
    let (root_path, targets_path) = (scratch.path("1.root.json"), scratch.path("targets.json"));
    for (body, staged) in [(&root, &root_path), (&targets, &targets_path)] {
        let body = text(&scratch.put("body.json", body));
        assert!(scratch.run(&["stage", &body, &text(staged)]).status.success());
    }
    fs::write(scratch.path("rebuilt.tar"), ARTIFACT).expect("rebuild");
    let statement = batch_statement(&[("root", "root", &root), ("targets", "targets", &targets)]);
    let signer = text(&scratch.stub_signer(&[&keys[1]], &message(&root)));
    scratch.prepare_batch(&keys[0], &message(&statement));
    let rebuilt = format!("{PATH}={}", text(&scratch.path("rebuilt.tar")));
    let (root_text, targets_text) = (text(&root_path), text(&targets_path));

    let key = text(&scratch.path("root-1"));
    let both = scratch.run(&["sign", &root_text, &targets_text, "--key", &key, "--signer", &signer, "--rebuilt", &rebuilt]);
    assert!(both.status.success(), "{}", stderr(&both));
    assert_eq!(scratch.calls(), vec![format!("-Y sign -n release-metadata-batch -f {key}")]);
    assert_eq!(fs::read(scratch.path("message")).expect("recorded message"), message(&statement));
    for path in [&root_path, &targets_path] {
        let entry = &signed_file(path)["signatures"][0];
        assert_eq!((&entry["keyid"], &entry["x-release-metadata-batch"]), (&json!(keys[0].id), &statement), "{}", path.display());
    }
    let shown = stdout(&both);
    assert!(shown.contains(&format!("{root_text}:\nroot version 1: 1 of 2 signatories count; missing root-2")), "{shown}");
    assert!(shown.contains(&format!("{targets_text}:\ntargets: 1 of 1 signatories count; met")), "{shown}");

    let second = scratch.run(&["sign", &root_text, "--key", &text(&scratch.path("root-2")), "--signer", &signer]);
    assert!(second.status.success(), "{}", stderr(&second));
    let signed_root = fs::read(&root_path).expect("root");
    let files = BTreeMap::from([("targets".to_owned(), fs::read(&targets_path).expect("targets"))]);
    let verified = read_release(signed_root, files, &online).expect("a reader starts from the root and reads its targets");
    assert_eq!(verified.target.role, "targets");
}

/// A signer that signs in process and records the namespace of each call.
struct CountingSigner<'a> {
    key: &'a SignatoryKey,
    calls: Mutex<Vec<String>>,
}

impl Signer for CountingSigner<'_> {
    fn sign(&self, key: &Path, namespace: &str, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.calls.lock().expect("calls").push(namespace.to_owned());
        InProcessSigner(self.key).sign(key, namespace, message)
    }
}

/// A root whose targets, snapshot and timestamp roles are Alice's one key.
fn alice_releases(alice: &SignatoryKey, root_keys: &[&SignatoryKey]) -> Value {
    let mut keys: Map<String, Value> = root_keys.iter().map(|k| (k.id.clone(), k.object.clone())).collect();
    keys.insert(alice.id.clone(), alice.object.clone());
    let root_ids: Vec<&str> = root_keys.iter().map(|k| k.id.as_str()).collect();
    json!({
        "_type": "root", "spec_version": "1.0.37", "consistent_snapshot": false,
        "version": 1, "expires": LATER, "keys": keys,
        "roles": {
            "root": { "keyids": root_ids, "threshold": 2 },
            "timestamp": { "keyids": [alice.id], "threshold": 1 },
            "snapshot": { "keyids": [alice.id], "threshold": 1 },
            "targets": { "keyids": [alice.id], "threshold": 1 },
        },
    })
}

#[test]
fn a_release_is_signed_with_one_call_and_lists_its_files_by_version() {
    let alice = SignatoryKey::new(20, "alice");
    let root_keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
    let root = serde_json::to_vec(&envelope(&alice_releases(&alice, &[&root_keys[0], &root_keys[1]]), Vec::new())).expect("root");
    let staged = stage(&message(&targets_body(&[PATH], None)), None, SystemTime::now()).expect("staged targets");
    let signer = CountingSigner { key: &alice, calls: Mutex::new(Vec::new()) };
    let rebuild = Rebuild::Rebuilt(BTreeMap::from([(PATH.to_owned(), ARTIFACT.to_vec())]));
    let (listed, later) = (BTreeMap::new(), SystemTime::now() + hours(24));
    let release = Release {
        root: &root, role: "targets", staged: &staged, delegator: None, rebuild: &rebuild, listed: &listed,
        previous_snapshot: None, previous_timestamp: None, snapshot_expires: later, timestamp_expires: later,
    };
    let signed = sign_release(&release, &signer, Path::new("alice")).expect("the release signs");
    assert_eq!(*signer.calls.lock().expect("calls"), ["release-metadata-batch"]);
    let (snapshot, timestamp): (Value, Value) =
        (serde_json::from_slice(&signed.snapshot).expect("json"), serde_json::from_slice(&signed.timestamp).expect("json"));
    assert_eq!(snapshot["signed"]["meta"], json!({ "targets.json": { "version": 1 } }));
    assert_eq!(timestamp["signed"]["meta"], json!({ "snapshot.json": { "version": 1 } }));

    let fetch = |targets: Vec<u8>| Fetched {
        roots: Vec::new(),
        timestamp: signed.timestamp.clone(),
        snapshot: signed.snapshot.clone(),
        targets: BTreeMap::from([("targets".to_owned(), targets)]),
    };
    let hashes = BTreeMap::from([("sha256".to_owned(), hex::encode(Sha256::digest(ARTIFACT)))]);
    let artifact = Artifact { length: ARTIFACT.len() as u64, hashes };
    let trusted = TrustedState::from_root(root.clone());
    let verified = verify(&trusted, &fetch(signed.targets.clone()), PATH, &artifact, SystemTime::now()).expect("verifies");
    assert_eq!(verified.target.role, "targets");

    // Another targets file of the same version, carrying the release's
    // signature, is refused: the statement names the real body's hash.
    let mut other: Value = serde_json::from_slice(&signed.targets).expect("json");
    other["signed"]["targets"]["fleet/chariot-6.6.tar"] = other["signed"]["targets"][PATH].clone();
    let refusal = verify(&trusted, &fetch(serde_json::to_vec(&other).expect("json")), PATH, &artifact, SystemTime::now())
        .expect_err("a substituted file of the same version");
    assert_eq!((refusal.role.as_str(), refusal.rule.code()), ("targets", "threshold"));
    let alice_verdict = refusal.signatories.iter().find(|v| v.signatory == "alice").expect("alice named");
    assert!(matches!(alice_verdict.faults.as_slice(), [(_, SignatureFault::BatchHash)]), "{:?}", alice_verdict.faults);
}

#[test]
fn a_batch_signer_that_one_files_thresholds_do_not_list_is_refused() {
    let keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
    let online = OnlineKey::new();
    let root = message(&root_body(1, &[&keys[0], &keys[1]], &keys[0], &online));
    let root = stage(&root, None, SystemTime::now()).expect("staged root");
    let targets = stage(&message(&targets_body(&[], None)), None, SystemTime::now()).expect("staged targets");
    let rebuild = Rebuild::Rebuilt(BTreeMap::new());
    let signer = CountingSigner { key: &keys[1], calls: Mutex::new(Vec::new()) };
    let refused = sign_ceremony(&root, None, &targets, &rebuild, &signer, Path::new("root-2")).expect_err("root-2 signs no targets");
    assert!(matches!(&refused, CeremonyError::KeyNotListed { role } if role == "targets"), "{refused:?}");

    let signer = CountingSigner { key: &keys[0], calls: Mutex::new(Vec::new()) };
    let signed = sign_ceremony(&root, None, &targets, &rebuild, &signer, Path::new("root-1")).expect("root-1 signs both");
    assert_eq!(*signer.calls.lock().expect("calls"), ["release-metadata-batch"]);
    let entry = |file: &[u8]| serde_json::from_slice::<Value>(file).expect("json")["signatures"][0].clone();
    assert_eq!(entry(&signed.root), entry(&signed.targets));
}

#[test]
fn the_release_command_signs_three_files_with_one_call_to_ssh_keygen() {
    let scratch = Scratch::new();
    let alice = SignatoryKey::new(20, "alice");
    let root_keys = [SignatoryKey::new(1, "root-1"), SignatoryKey::new(2, "root-2")];
    let private = alice.private.to_openssh(LineEnding::LF).expect("private key file");
    fs::write(scratch.path("alice"), private.as_bytes()).expect("key file");
    fs::set_permissions(scratch.path("alice"), fs::Permissions::from_mode(0o600)).expect("private");
    let calls = text(&scratch.path("calls"));
    let signer = text(&script(&scratch, "ssh-keygen-recorded", &format!("printf '%s\\n' \"$*\" >> '{calls}'\nexec ssh-keygen \"$@\"\n")));
    let root = alice_releases(&alice, &[&root_keys[0], &root_keys[1]]);
    let trusted = text(&scratch.put("root.json", &envelope(&root, Vec::new())));
    let audiences = json!({
        "keys": listing(&[&alice.object], &[alice.id.as_str()]),
        "roles": [{ "name": "fleet", "keyids": [alice.id], "threshold": 1, "terminating": true, "paths": ["fleet/*"] }],
    });
    let top = targets_body(&[], Some(audiences));
    let delegator = text(&scratch.put("targets.json", &envelope(&top, vec![alice.signature(&message(&top))])));
    let body = text(&scratch.put("fleet.body.json", &targets_body(&[PATH], None)));
    let fleet = text(&scratch.path("fleet.json"));
    assert!(scratch.run(&["stage", &body, &fleet, "--role", "fleet"]).status.success());
    fs::write(scratch.path("rebuilt.tar"), ARTIFACT).expect("rebuild");
    let rebuilt = format!("{PATH}={}", text(&scratch.path("rebuilt.tar")));
    let (snapshot, timestamp) = (text(&scratch.path("snapshot.json")), text(&scratch.path("timestamp.json")));

    let release = scratch.run(&[
        "release", &fleet, "--trusted", &trusted, "--delegator", &delegator, "--targets", &delegator,
        "--snapshot", &snapshot, "--timestamp", &timestamp, "--snapshot-expires-in", "7d",
        "--timestamp-expires-in", "1d", "--key", &text(&scratch.path("alice")), "--signer", &signer, "--rebuilt", &rebuilt,
    ]);
    assert!(release.status.success(), "{}", stderr(&release));
    assert_eq!(scratch.calls().len(), 1, "{:?}", scratch.calls());
    assert!(scratch.calls()[0].starts_with("-Y sign -n release-metadata-batch -f "), "{:?}", scratch.calls());
    assert!(stdout(&release).contains("fleet: 1 of 1 signatories count; met"), "{}", stdout(&release));

    let read = |path: &str| fs::read(path).expect("written");
    let fetched = Fetched {
        roots: Vec::new(),
        timestamp: read(&timestamp),
        snapshot: read(&snapshot),
        targets: BTreeMap::from([("targets".to_owned(), read(&delegator)), ("fleet".to_owned(), read(&fleet))]),
    };
    let hashes = BTreeMap::from([("sha256".to_owned(), hex::encode(Sha256::digest(ARTIFACT)))]);
    let artifact = Artifact { length: ARTIFACT.len() as u64, hashes };
    let trusted = TrustedState::from_root(read(&trusted));
    let verified = verify(&trusted, &fetched, PATH, &artifact, SystemTime::now()).expect("the release verifies");
    assert_eq!(verified.target.role, "fleet");
}
```
