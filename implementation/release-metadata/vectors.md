# The conformance vectors of x0k-release-metadata

```turtle folio:document
implementation:release-metadata\/vectors a x0k:Implementation ;
    x0k:status "draft" ;
    x0k:summary "Signed repositories on disk, one per claim of the release-metadata decision, each with the outcome the verifier must reach, and the generator that writes them." ;
    x0k:concerns "trust", "delivery", "signing", "conformance" ;
    x0k:cites implementation:release-metadata\/release-metadata,
        implementation:release-metadata\/hardware-kit ;
    x0k:implements design:distribution-and-updates ;
    x0k:motivatedBy architecture:release-metadata ;
    folio:tangleCrate "crates/x0k-release-metadata" ;
    folio:tangleRoot "tests/conformance/main.rs" .
```

A verifier's claims are only as good as the cases that test them. Each
**conformance vector** is a small signed repository on disk, under the
crate's `vectors/` directory, with the outcome the verifier must reach:
verified by a named role, or refused by a named role under a named rule.
The vectors are files, not code, so another implementation of the decision
can run the same cases. Each one names the section of
`x0k:architecture/release-metadata` whose *Checked by* line it answers.

A vector directory holds:

- `trusted/root.json`, and `trusted/timestamp.json` where the case needs a
  trusted timestamp: the reader's state before the update;
- `fetched/`: what the embedder fetched, with TUF's file names. A newer
  root is `N.root.json`; the timestamp and snapshot are `timestamp.json`
  and `snapshot.json`; every other file is the targets role of its stem;
- `case.json`: the decision section, the claim, the time, the target path
  with the artifact's length and hashes, and the expected outcome.

The cast is the chapter's (`implementation:release-metadata/release-metadata`).
Alice signs with a laptop key or a token, Bob with one key, Carol with an
SSH key, and one online key signs the snapshot and timestamp. Four root
keys belong to four other people.

## The claims

| Vector | Section | Claim |
|---|---|---|
| `s1-baseline-verifies` | §1 | A target that a delegated role lists, with every file signed, current and consistent, verifies. |
| `s1-lower-timestamp-version` | §1 | A timestamp lower than the trusted one is refused as a rollback. |
| `s1-expired-timestamp` | §1 | An expired timestamp is refused. |
| `s2-fleet-artifact-looked-up-for-pilot` | §2 | An artifact signed for `fleet` is refused when looked up for `pilot`, even when the `fleet` role lists the `pilot` path. |
| `s2-path-two-levels-under-audience` | §2 | A path two levels under an audience is refused as unknown, even when the delegation's patterns cover it and the audience role lists it. |
| `s3-sshsig-verifies` | §3 | An SSHSIG signature under the namespace `release-metadata` counts. |
| `s3-sshsig-wrong-namespace` | §3 | An SSHSIG signature under another namespace does not count. |
| `s3-sshsig-key-line-with-comment` | §3 | An SSHSIG key whose line carries a comment is malformed, and its signature does not count. |
| `s4-one-signatory-two-keys` | §4 | One signatory signing with two keys does not meet a threshold of two. |
| `s4-two-signatories-meet-two` | §4 | Two signatories with one key each meet a threshold of two. |
| `s4-signatory-rule-unmet` | §4 | A signatory whose rule requires two keys does not count with one. |
| `s4-signatory-rule-met` | §4 | That signatory counts with two. |
| `s4-one-key-two-signatories` | §4 | One public key listed under two signatories in a delegation is refused. |
| `s4-root-lists-one-key-twice` | §4 | A root that lists one public key under two signatories is refused as `root`, before any release is read. |
| `s4-one-key-in-two-forms` | §4 | A root that lists one Ed25519 key in TUF's hex form and again as an SSH key line is refused. |
| `s4-unnamed-keys-count-as-tuf` | §4 | Keys that name no signatory are each their own signatory, so two of them meet a threshold of two. |
| `s5-rotation` | §5 | A root that rotates its keys verifies when the old and the new thresholds both sign it. |
| `s5-removed-key` | §5 | A key that a root removed does not count toward the next root, even in a root that adds it back. |
| `s5-new-keys-only` | §5 | A root signed only by its new keys is refused. |
| `s5-new-root-without-its-keys` | §5 | A root signed only by the old keys, not by its own, is refused. |
| `s5-root-skips-version` | §5 | A root that skips a version is refused. |
| `s3-software-enclave-verifies` | §3 | A P-256 SSHSIG signature, the kind a Secure Enclave key makes through Secretive, counts (software-made). |
| `s3-software-fido2-ed25519-verifies` | §3 | An `sk-ssh-ed25519` signature over the U2F blob, with its flags and counter, counts (software-made). |
| `s3-software-fido2-ecdsa-verifies` | §3 | An `sk-ecdsa-sha2-nistp256` signature over the U2F blob counts (software-made). |
| `s3-software-passkey-verifies` | §3 | A `webauthn-sk-ecdsa-sha2-nistp256` signature, whose client data carries the SSHSIG blob as its challenge, counts (software-made). |
| `s3-software-passkey-other-challenge` | §3 | A WebAuthn signature whose client data carries another challenge does not count, though the authenticator signed it (software-made). |
| `s4-software-touch-missing` | §4 | A token signature without the touch flag does not count for a signatory whose rule demands one (software-made). |
| `s4-software-touch-present` | §4 | The same token's signature with the touch flag counts (software-made). |
| `s4-presence-rule-on-non-sk-key` | §4 | A root whose presence rule names a signatory holding a key that is not an `sk` key is refused, before any release is read. |
| `hw-fido2-ed25519` | §3, §4 | A FIDO2 token's own `sk-ssh-ed25519` signature, made with a touch, counts for a signatory whose rule demands the touch (hand-signed). |
| `hw-fido2-ecdsa` | §3, §4 | A FIDO2 token's own `sk-ecdsa-sha2-nistp256` signature, made with a touch, counts for a signatory whose rule demands the touch (hand-signed). |
| `hw-enclave-ecdsa` | §3 | A Secure Enclave key's own `ecdsa-sha2-nistp256` signature, made through Secretive, counts (hand-signed). |
| `hw-passkey-webauthn` | §3 | A phone passkey's own WebAuthn signature, made through Chrome with the origin `http://localhost:8000`, counts (hand-signed). |
| `tuf-baseline-verifies` | §4 | A TUF-native repository, whose keys and root still carry the extension fields, verifies (stock clients agree). |
| `tuf-expired-timestamp` | §1 | Its expired timestamp is refused (stock clients agree). |
| `tuf-lower-timestamp-version` | §1 | Its timestamp lower than the trusted one is refused (stock clients agree). |
| `tuf-fleet-artifact-looked-up-for-pilot` | §2 | Its fleet artifact looked up for pilot is refused (stock clients agree). |
| `tuf-threshold-unmet` | §4 | One signature where its role needs two is refused (stock clients agree). |
| `tuf-rotation-verifies` | §5 | Its root rotation signed by both thresholds verifies (stock clients agree). |
| `tuf-new-keys-only` | §5 | Its root signed only by the new keys is refused (stock clients agree). |
| `s8-advance-delegation-verifies` | §8 | A target that a session key signs, under a delegation of its version's files that the audience's signatories made for less than a day, verifies. |
| `s8-advance-delegation-other-version` | §8 | A target for another version is refused, even when the session key signs it. |
| `s8-advance-delegation-expired` | §8 | A target under a delegation whose metadata has expired is refused. |
| `s8-public-delegation-missing-signatory` | §8 | A delegation for an audience the root marks public, signed by two of its role's three signatories, is refused. |
| `s8-public-delegation-every-signatory` | §8 | That delegation, signed by every signatory its role lists, verifies. |
| `s8-public-release-meets-its-threshold` | §8 | A release in a public audience whose file delegates nothing still needs only its role's threshold. |
| `s6-targets-signed-only-by-online-key` | §6 | Targets metadata that only the online key signed is refused: the key on the build server signs freshness, never a release. |

The four `hw-` vectors are hand-signed data: the operator's own FIDO2
token, Secure Enclave key and phone passkey signed them once, through the
kit of `implementation:release-metadata/hardware-kit`, and their files
are kept exactly as the kit wrote them. The generator does not write
them and never removes them. They are remade only by running the kit
again, `kit/sign-hardware-vectors.sh` on a Mac with the devices, which
makes fresh keys and so new files. Their roots, top-level targets and
online keys are the kit's software keys; only the `fleet` signature is
the device's.

The other §3 vectors sign through `ssh-key`, not through `ssh-keygen`. Ed25519
signatures are deterministic and SSHSIG adds no randomness, so `ssh-keygen
-Y sign` over the same key, namespace, hash and message writes the same
envelope; a vector made by the real signer is the hardware slice's work.
An SSH key's object holds the line `ssh-keygen -y` prints for it, without
the comment, and its `keytype` is `ssh-ed25519`.

## Running them

The crate's integration tests are one suite, one test binary: the vectors
here, the purity check of the previous chapter, and the ceremony tests
(`implementation:release-metadata/ceremony`), whose stub signer program is
a shell script and so runs on Unix only.

<a name="chunk-suite"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#suite`</sub>

```rust {#suite file="tests/conformance/main.rs"}
//! The crate's integration tests: the conformance vectors, the purity check
//! and the ceremony commands.

#![allow(
    clippy::result_large_err,
    reason = "the helpers return the crate's Refusal, whose size the crate allows for the same reason"
)]

#[cfg(unix)]
mod ceremony;
mod purity;
mod vectors;
```

The test reads each vector through the public contract only: it builds a
`TrustedState` and a `Fetched` from the files, calls `verify`, and compares
the outcome with `case.json`. A refusal is compared by its role and its
rule's code.

<a name="chunk-vector-tests"></a><sub>[`tests/conformance/vectors.rs`](../../crates/x0k-release-metadata/tests/conformance/vectors.rs) · `#vector-tests` · assembles [load-vector](#chunk-load-vector) · [check-vector](#chunk-check-vector) · [vector-list](#chunk-vector-list) · [vector-details](#chunk-vector-details)</sub>

```rust {#vector-tests file="tests/conformance/vectors.rs"}
//! The conformance vectors: one test per claim of the release-metadata decision.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use x0k_release_metadata::{
    parse_utc, verify, Artifact, Fetched, Refusal, Rule, SignatureFault, TrustedState, Verified,
};

#[derive(Deserialize)]
struct Case {
    decision: String,
    claim: String,
    now: String,
    target: Target,
    expect: Expect,
}

#[derive(Deserialize)]
struct Target {
    path: String,
    length: u64,
    hashes: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Expect {
    Verified { role: String },
    Refused { role: String, rule: String },
}

fn vectors_root() -> PathBuf {
    let crate_dir = std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    PathBuf::from(crate_dir).join("vectors")
}

fn vector_dir(name: &str) -> PathBuf {
    vectors_root().join(name)
}

<<load-vector>>

<<check-vector>>

<<vector-list>>

<<vector-details>>
```

Loading turns the directory into the verifier's inputs. Newer roots are
sorted by the version in their file names.

<a name="chunk-load-vector"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#load-vector`</sub>

```rust {#load-vector}
fn load(dir: &Path, case: &Case) -> Result<Verified, Refusal> {
    load_with_root(dir, case, fs::read(dir.join("trusted/root.json")).expect("trusted root"))
}

/// Loads a vector as a reader that trusts `root` instead of the vector's own.
fn load_with_root(dir: &Path, case: &Case, root: Vec<u8>) -> Result<Verified, Refusal> {
    let trusted = TrustedState {
        root,
        timestamp: fs::read(dir.join("trusted/timestamp.json")).ok(),
        snapshot: fs::read(dir.join("trusted/snapshot.json")).ok(),
        targets: BTreeMap::new(),
    };
    let mut fetched = Fetched::default();
    let mut roots = Vec::new();
    for entry in fs::read_dir(dir.join("fetched")).expect("fetched directory") {
        let path = entry.expect("directory entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).expect("file name").to_owned();
        let bytes = fs::read(&path).expect("fetched file");
        if let Some(version) = name.strip_suffix(".root.json") {
            roots.push((version.parse::<u64>().expect("root version"), bytes));
        } else if name == "timestamp.json" {
            fetched.timestamp = bytes;
        } else if name == "snapshot.json" {
            fetched.snapshot = bytes;
        } else if let Some(role) = name.strip_suffix(".json") {
            fetched.targets.insert(role.to_owned(), bytes);
        }
    }
    roots.sort_by_key(|(version, _)| *version);
    fetched.roots = roots.into_iter().map(|(_, bytes)| bytes).collect();
    let artifact = Artifact { length: case.target.length, hashes: case.target.hashes.clone() };
    let now = parse_utc(&case.now).expect("case time");
    verify(&trusted, &fetched, &case.target.path, &artifact, now)
}
```

A failed check prints the vector, its section and its claim, so the red
names what no longer holds.

<a name="chunk-check-vector"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#check-vector`</sub>

```rust {#check-vector}
fn check(name: &str) -> Result<Verified, Refusal> {
    let dir = vector_dir(name);
    let case: Case = serde_json::from_slice(&fs::read(dir.join("case.json")).expect("case.json"))
        .expect("case.json parses");
    let outcome = load(&dir, &case);
    let (decision, claim) = (&case.decision, &case.claim);
    match (&case.expect, &outcome) {
        (Expect::Verified { role }, Ok(verified)) => {
            assert_eq!(&verified.target.role, role, "{name} ({decision}): {claim}");
        }
        (Expect::Refused { role, rule }, Err(refusal)) => {
            assert_eq!(
                (refusal.role.as_str(), refusal.rule.code()),
                (role.as_str(), rule.as_str()),
                "{name} ({decision}): {claim}: refused with {refusal}"
            );
        }
        (expect, outcome) => {
            panic!("{name} ({decision}): {claim}\nexpected {expect:?}\ngot {outcome:?}")
        }
    }
    outcome
}
```

Each vector is one named test. The list is also checked against the
directory, so a vector on disk without a test, or a test without its
vector, is red.

<a name="chunk-vector-list"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#vector-list`</sub>

```rust {#vector-list}
macro_rules! vectors {
    ($($test:ident => $name:literal,)*) => {
        const ALL: &[&str] = &[$($name),*];
        $(
            #[test]
            fn $test() {
                let _ = check($name);
            }
        )*
    };
}

vectors! {
    a_consistent_signed_repository_verifies => "s1-baseline-verifies",
    a_lower_timestamp_version_is_refused => "s1-lower-timestamp-version",
    an_expired_timestamp_is_refused => "s1-expired-timestamp",
    a_fleet_artifact_is_refused_when_looked_up_for_pilot => "s2-fleet-artifact-looked-up-for-pilot",
    a_path_two_levels_under_an_audience_is_refused => "s2-path-two-levels-under-audience",
    an_sshsig_signature_under_the_namespace_counts => "s3-sshsig-verifies",
    an_sshsig_signature_under_another_namespace_does_not_count => "s3-sshsig-wrong-namespace",
    an_sshsig_key_line_with_a_comment_does_not_count => "s3-sshsig-key-line-with-comment",
    one_signatory_with_two_keys_misses_a_threshold_of_two => "s4-one-signatory-two-keys",
    two_signatories_meet_a_threshold_of_two => "s4-two-signatories-meet-two",
    a_signatory_short_of_their_rule_does_not_count => "s4-signatory-rule-unmet",
    a_signatory_meeting_their_rule_counts => "s4-signatory-rule-met",
    one_key_listed_under_two_signatories_is_refused => "s4-one-key-two-signatories",
    a_root_listing_one_key_twice_is_refused_as_root => "s4-root-lists-one-key-twice",
    one_key_in_two_forms_is_one_key => "s4-one-key-in-two-forms",
    keys_naming_no_signatory_count_as_tuf_counts => "s4-unnamed-keys-count-as-tuf",
    a_rotation_signed_by_both_thresholds_verifies => "s5-rotation",
    a_removed_key_does_not_count_toward_the_next_root => "s5-removed-key",
    a_root_signed_only_by_its_new_keys_is_refused => "s5-new-keys-only",
    a_root_its_own_keys_did_not_sign_is_refused => "s5-new-root-without-its-keys",
    a_root_that_skips_a_version_is_refused => "s5-root-skips-version",
    targets_signed_only_by_the_online_key_are_refused => "s6-targets-signed-only-by-online-key",
    an_advance_delegation_for_one_version_verifies => "s8-advance-delegation-verifies",
    another_version_under_an_advance_delegation_is_refused => "s8-advance-delegation-other-version",
    a_target_under_an_expired_delegation_is_refused => "s8-advance-delegation-expired",
    a_public_delegation_missing_a_signatory_is_refused => "s8-public-delegation-missing-signatory",
    a_public_delegation_signed_by_every_signatory_verifies => "s8-public-delegation-every-signatory",
    a_public_release_needs_only_its_threshold => "s8-public-release-meets-its-threshold",
    a_secure_enclave_signature_counts => "s3-software-enclave-verifies",
    a_fido2_ed25519_signature_counts => "s3-software-fido2-ed25519-verifies",
    a_fido2_ecdsa_signature_counts => "s3-software-fido2-ecdsa-verifies",
    a_passkey_signature_counts => "s3-software-passkey-verifies",
    a_passkey_signature_over_another_challenge_does_not_count => "s3-software-passkey-other-challenge",
    a_token_signature_without_the_touch_flag_does_not_count => "s4-software-touch-missing",
    a_token_signature_with_the_touch_flag_counts => "s4-software-touch-present",
    a_presence_rule_on_a_key_without_flags_is_refused => "s4-presence-rule-on-non-sk-key",
    a_real_fido2_ed25519_signature_counts => "hw-fido2-ed25519",
    a_real_fido2_ecdsa_signature_counts => "hw-fido2-ecdsa",
    a_real_secure_enclave_signature_counts => "hw-enclave-ecdsa",
    a_real_passkey_signature_counts => "hw-passkey-webauthn",
    a_tuf_native_repository_verifies => "tuf-baseline-verifies",
    a_tuf_native_expired_timestamp_is_refused => "tuf-expired-timestamp",
    a_tuf_native_lower_timestamp_is_refused => "tuf-lower-timestamp-version",
    a_tuf_native_fleet_artifact_is_refused_for_pilot => "tuf-fleet-artifact-looked-up-for-pilot",
    a_tuf_native_unmet_threshold_is_refused => "tuf-threshold-unmet",
    a_tuf_native_rotation_verifies => "tuf-rotation-verifies",
    a_tuf_native_root_signed_only_by_new_keys_is_refused => "tuf-new-keys-only",
}

#[test]
fn every_vector_on_disk_has_a_test() {
    let on_disk: BTreeSet<String> = fs::read_dir(vectors_root())
        .expect("vectors directory")
        .map(|entry| entry.expect("directory entry").file_name().to_string_lossy().into_owned())
        .collect();
    let named: BTreeSet<String> = ALL.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(on_disk, named);
}
```

Seven claims need more than a role and a rule. §4 asks the refusal to name
each signatory that signed but did not count, and why. §3 asks it to name a
signature under another namespace, and a key line that is not in
`ssh-keygen`'s form is a malformed key, not an invalid signature. §8's
refusal of a public delegation names the signatory who did not sign. §4's
touch refusal names the missing flag, and a WebAuthn signature over
another challenge is named as such. §7
says the outcome carries the new trusted state, which after a rotation is
the newest root.

<a name="chunk-vector-details"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#vector-details`</sub>

```rust {#vector-details}
#[test]
fn the_refusal_names_alice_who_signed_twice_and_counted_once() {
    let refusal = check("s4-one-signatory-two-keys").expect_err("refused");
    let alice = refusal.signatories.iter().find(|v| v.signatory == "alice").expect("alice named");
    assert_eq!((alice.valid_keys, alice.required_keys, alice.counted), (2, 1, true));
    assert!(matches!(refusal.rule, Rule::Threshold { threshold: 2, counted: 1 }));
}

#[test]
fn the_refusal_names_the_wrong_namespace() {
    let refusal = check("s3-sshsig-wrong-namespace").expect_err("refused");
    let carol = refusal.signatories.iter().find(|v| v.signatory == "carol").expect("carol named");
    assert!(matches!(carol.faults.as_slice(), [(_, SignatureFault::Namespace(ns))] if ns == "git"));
}

#[test]
fn the_refusal_names_a_key_line_with_a_comment_as_a_malformed_key() {
    let refusal = check("s3-sshsig-key-line-with-comment").expect_err("refused");
    let carol = refusal.signatories.iter().find(|v| v.signatory == "carol").expect("carol named");
    assert!(matches!(carol.faults.as_slice(), [(_, SignatureFault::Key)]));
}
```

A real token's signature carries the flags the token set, and the
signatory's rule decides which ones count (§4). The two FIDO2 vectors'
tokens set the touch flag and not user verification. So a reader whose
trusted root demands `user-verified` as well does not count the same
signatures, and the refusal names the missing flag.

<a name="chunk-vector-details-2"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#vector-details` · continues</sub>

```rust {#vector-details}

/// Verifies vector `name` as a reader whose trusted root `edit` changed.
fn check_under_root(name: &str, edit: impl FnOnce(&mut serde_json::Value)) -> Result<Verified, Refusal> {
    let dir = vector_dir(name);
    let case: Case = serde_json::from_slice(&fs::read(dir.join("case.json")).expect("case.json")).expect("case.json parses");
    let mut root: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("trusted/root.json")).expect("trusted root")).expect("root parses");
    edit(&mut root);
    load_with_root(&dir, &case, serde_json::to_vec(&root).expect("root"))
}

#[test]
fn a_real_token_signature_does_not_count_where_the_rule_demands_a_flag_it_lacks() {
    for name in ["hw-fido2-ed25519", "hw-fido2-ecdsa"] {
        let refusal = check_under_root(name, |root| {
            root["signed"]["x-release-metadata-signatories"]["operator"]["flags"] =
                serde_json::json!(["user-present", "user-verified"]);
        })
        .expect_err("refused");
        assert_eq!((refusal.role.as_str(), refusal.rule.code()), ("fleet", "threshold"), "{name}");
        let operator = refusal.signatories.iter().find(|v| v.signatory == "operator").expect("operator named");
        assert!(
            matches!(operator.faults.as_slice(), [(_, SignatureFault::MissingFlag("user-verified"))]),
            "{name}: {:?}",
            operator.faults
        );
    }
}
```

<a name="chunk-vector-details-3"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#vector-details` · continues</sub>

```rust {#vector-details}

#[test]
fn the_touch_refusal_names_the_missing_flag() {
    let refusal = check("s4-software-touch-missing").expect_err("refused");
    let dave = refusal.signatories.iter().find(|v| v.signatory == "dave").expect("dave named");
    assert!(matches!(dave.faults.as_slice(), [(_, SignatureFault::MissingFlag("user-present"))]), "{:?}", dave.faults);
}

#[test]
fn the_passkey_refusal_names_the_client_data() {
    let refusal = check("s3-software-passkey-other-challenge").expect_err("refused");
    let grace = refusal.signatories.iter().find(|v| v.signatory == "grace").expect("grace named");
    assert!(matches!(grace.faults.as_slice(), [(_, SignatureFault::ClientData)]), "{:?}", grace.faults);
}

#[test]
fn the_public_delegation_refusal_names_the_signatory_who_did_not_sign() {
    let refusal = check("s8-public-delegation-missing-signatory").expect_err("refused");
    let missing: Vec<&str> = refusal.signatories.iter().filter(|v| !v.counted).map(|v| v.signatory.as_str()).collect();
    assert_eq!(missing, ["carol"]);
}

#[test]
fn the_new_trusted_state_holds_the_rotated_root() {
    let verified = check("s5-rotation").expect("verified");
    let newest = fs::read(vector_dir("s5-rotation").join("fetched/2.root.json")).expect("root 2");
    assert_eq!(verified.trusted.root, newest);
}
```

## The generator

The vectors are written by an example program, so they can be regenerated
and reviewed as a diff: `cargo run -p x0k-release-metadata --example
make_vectors -- vectors`, from the crate directory. Every key comes from a
fixed seed and both schemes sign deterministically, so a run over unchanged
code writes the same bytes.

<a name="chunk-generator"></a><sub>[`examples/make_vectors.rs`](../../crates/x0k-release-metadata/examples/make_vectors.rs) · `#generator` · assembles [test-key](#chunk-test-key) · [cast](#chunk-cast) · [bodies](#chunk-bodies) · [parts](#chunk-parts) · [write-vector](#chunk-write-vector) · [vector-cases](#chunk-vector-cases)</sub>

```rust {#generator file="examples/make_vectors.rs"}
//! Writes the conformance vectors: `cargo run --example make_vectors -- vectors`.

use std::fs;
use std::path::Path;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};
use ssh_encoding::Encode;
use ssh_key::private::Ed25519Keypair;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PrivateKey, PublicKey};
use x0k_release_metadata::{canonical_json, key_id, NAMESPACE};

const NOW: &str = "2026-11-05T00:00:00Z";
const LATER: &str = "2030-01-01T00:00:00Z";
const PAST: &str = "2026-01-01T00:00:00Z";
const ARTIFACT: &[u8] = b"chariot 1.0\n";
const FLEET_PATH: &str = "fleet/chariot-1.0.tar";
const PILOT_PATH: &str = "pilot/chariot-1.0.tar";
const DEEP_FLEET_PATH: &str = "fleet/chariot/chariot-1.0.tar";
const SOON: &str = "2026-11-05T12:00:00Z";
const JUST_PAST: &str = "2026-11-04T12:00:00Z";
const ADVANCE_PATH: &str = "fleet/chariot-1.1-x86_64-linux.tar";
const OTHER_VERSION_PATH: &str = "fleet/chariot-1.2-x86_64-linux.tar";
const PUBLIC_ADVANCE_PATH: &str = "public/chariot-1.1-x86_64-linux.tar";
const PUBLIC_PATH: &str = "public/chariot-1.0.tar";

<<test-key>>

<<cast>>

<<bodies>>

<<parts>>

<<write-vector>>

<<vector-cases>>

fn main() {
    let out = std::env::args().nth(1).expect("usage: make_vectors <directory>");
    let cast = Cast::new();
    for vector in vectors(&cast) {
        write(Path::new(&out), &cast, vector);
    }
}
```

A test key is its TUF key object, its id and its signer. An SSH key signs
under the namespace it is given, which is `release-metadata` unless a
vector asks for another. A key may name no signatory and no custody, as a
plain TUF key does.

<a name="chunk-test-key"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#test-key` · assembles [hardware-stand-ins](#chunk-hardware-stand-ins)</sub>

```rust {#test-key}
#[derive(Clone)]
struct TestKey {
    id: String,
    object: Value,
    signer: Signer,
}

#[derive(Clone)]
enum Signer {
    Ed25519(SigningKey),
    Sshsig(PrivateKey, &'static str),
    /// A software stand-in for a hardware signer, with its key's wire encoding.
    Hardware { wire: Vec<u8>, kind: Hardware },
}

impl TestKey {
    fn ed25519(seed: u8, signatory: &str, custody: &str) -> Self {
        Self::plain(seed).named(signatory, custody)
    }

    /// A TUF `ed25519` key that names no signatory and no custody.
    fn plain(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public = hex::encode(key.verifying_key().as_bytes());
        Self::new("ed25519", "ed25519", public, Signer::Ed25519(key))
    }

    fn sshsig(seed: u8, signatory: &str) -> Self {
        Self::sshsig_line(seed, |line| line).named(signatory, "software")
    }

    /// An SSHSIG key whose `keyval.public` is `ssh-keygen`'s line, as `edit` leaves it.
    fn sshsig_line(seed: u8, edit: impl FnOnce(String) -> String) -> Self {
        let pair = Ed25519Keypair::from_seed(&[seed; 32]);
        let line = PublicKey::from(KeyData::Ed25519(pair.public)).to_openssh().expect("key line");
        let signer = Signer::Sshsig(PrivateKey::from(pair), NAMESPACE);
        Self::new("ssh-ed25519", "sshsig-ssh-ed25519", edit(line), signer)
    }

    fn new(keytype: &str, scheme: &str, public: String, signer: Signer) -> Self {
        let object = json!({ "keytype": keytype, "scheme": scheme, "keyval": { "public": public } });
        Self { id: key_id(&object).expect("key id"), object, signer }
    }

    fn named(mut self, signatory: &str, custody: &str) -> Self {
        self.object["x-release-metadata-signatory"] = json!(signatory);
        self.object["x-release-metadata-custody"] = json!(custody);
        self.id = key_id(&self.object).expect("key id");
        self
    }

    fn under_namespace(&self, namespace: &'static str) -> Self {
        let mut key = self.clone();
        if let Signer::Sshsig(_, ns) = &mut key.signer {
            *ns = namespace;
        }
        key
    }

    fn sign(&self, message: &[u8]) -> Value {
        let sig = match &self.signer {
            Signer::Ed25519(key) => hex::encode(key.sign(message).to_bytes()),
            Signer::Sshsig(key, namespace) => {
                let envelope = key.sign(namespace, HashAlg::Sha512, message).expect("sshsig");
                let mut blob = Vec::new();
                envelope.encode(&mut blob).expect("sshsig encoding");
                hex::encode(blob)
            }
            Signer::Hardware { wire, kind } => hex::encode(kind.sshsig(wire, message)),
        };
        json!({ "keyid": self.id, "sig": sig })
    }
}

<<hardware-stand-ins>>

fn signed(body: Value, signers: &[&TestKey]) -> Value {
    let message = canonical_json(&body).expect("canonical body");
    let signatures: Vec<Value> = signers.iter().map(|key| key.sign(&message)).collect();
    json!({ "signed": body, "signatures": signatures })
}
```

The hardware schemes of §3 sign through a Secure Enclave, a FIDO2 token
or a WebAuthn authenticator. The generator stands in for each with a
software key that writes the same structures: an SSHSIG envelope around a
P-256 signature, the U2F blob of OpenSSH `PROTOCOL.u2f` with its flags
and counter, and WebAuthn client data around the SSHSIG blob as its
challenge. These vectors are software-made, and their names say so; a
vector signed by the real device is made by the kit of
`implementation:release-metadata/hardware-kit` and carries the prefix
`hw-`.

<a name="chunk-hardware-stand-ins"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#hardware-stand-ins`</sub>

```rust {#hardware-stand-ins}
type P256Key = p256::ecdsa::SigningKey;

/// What a hardware signer writes, made with a software key.
#[derive(Clone)]
enum Hardware {
    Enclave(P256Key),
    TokenEd25519 { key: SigningKey, flags: u8 },
    TokenEcdsa { key: P256Key, flags: u8 },
    Passkey { key: P256Key, flags: u8, challenge: Option<&'static [u8]> },
}

const TOKEN_APPLICATION: &str = "ssh:";
const PASSKEY_RP_ID: &str = "localhost";
const PASSKEY_ORIGIN: &str = "http://localhost:8000";
const COUNTER: u32 = 7;

impl TestKey {
    fn enclave(seed: u8, signatory: &str) -> Self {
        let key = p256_key(seed);
        let wire = ssh_wire(&[b"ecdsa-sha2-nistp256", b"nistp256", &p256_point(&key)]);
        Self::hardware("ecdsa-sha2-nistp256", "sshsig-ecdsa-sha2-nistp256", wire, Hardware::Enclave(key))
            .named(signatory, "secure-enclave")
    }

    fn token_ed25519(seed: u8, signatory: &str, flags: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public = key.verifying_key().to_bytes();
        let wire = ssh_wire(&[b"sk-ssh-ed25519@openssh.com", &public, TOKEN_APPLICATION.as_bytes()]);
        let kind = Hardware::TokenEd25519 { key, flags };
        Self::hardware("sk-ssh-ed25519@openssh.com", "sshsig-sk-ssh-ed25519", wire, kind).named(signatory, "fido2")
    }

    fn token_ecdsa(seed: u8, signatory: &str, flags: u8) -> Self {
        let key = p256_key(seed);
        let wire = sk_ecdsa_wire(&key, TOKEN_APPLICATION);
        let kind = Hardware::TokenEcdsa { key, flags };
        Self::hardware("sk-ecdsa-sha2-nistp256@openssh.com", "sshsig-sk-ecdsa-sha2-nistp256", wire, kind)
            .named(signatory, "fido2")
    }

    fn passkey(seed: u8, signatory: &str, challenge: Option<&'static [u8]>) -> Self {
        let key = p256_key(seed);
        let wire = sk_ecdsa_wire(&key, PASSKEY_RP_ID);
        let kind = Hardware::Passkey { key, flags: 0x05, challenge };
        Self::hardware("sk-ecdsa-sha2-nistp256@openssh.com", "sshsig-sk-ecdsa-sha2-nistp256", wire, kind)
            .named(signatory, "passkey")
    }

    fn hardware(keytype: &str, scheme: &str, wire: Vec<u8>, kind: Hardware) -> Self {
        let line = format!("{keytype} {}", Base64::encode_string(&wire));
        Self::new(keytype, scheme, line, Signer::Hardware { wire, kind })
    }
}

impl Hardware {
    /// The SSHSIG envelope this signer writes over `message`, for the key `public`.
    fn sshsig(&self, public: &[u8], message: &[u8]) -> Vec<u8> {
        let mut signed = b"SSHSIG".to_vec();
        signed.extend(ssh_wire(&[NAMESPACE.as_bytes(), b"", b"sha512", &Sha512::digest(message)]));
        let token_data = |flags: u8| sk_data(TOKEN_APPLICATION, flags, &Sha256::digest(&signed));
        let blob = match self {
            Hardware::Enclave(key) => ssh_wire(&[b"ecdsa-sha2-nistp256", &p256_signature(key, &signed)]),
            Hardware::TokenEd25519 { key, flags } => {
                let signature = key.sign(&token_data(*flags)).to_bytes();
                [ssh_wire(&[b"sk-ssh-ed25519@openssh.com", &signature]), sk_trailer(*flags)].concat()
            }
            Hardware::TokenEcdsa { key, flags } => {
                let signature = p256_signature(key, &token_data(*flags));
                [ssh_wire(&[b"sk-ecdsa-sha2-nistp256@openssh.com", &signature]), sk_trailer(*flags)].concat()
            }
            Hardware::Passkey { key, flags, challenge } => {
                let challenge = Base64UrlUnpadded::encode_string(challenge.unwrap_or(&signed));
                let client_data = format!(
                    r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{PASSKEY_ORIGIN}","crossOrigin":false}}"#
                );
                let data = sk_data(PASSKEY_RP_ID, *flags, &Sha256::digest(client_data.as_bytes()));
                let algorithm = b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com";
                let after = ssh_wire(&[PASSKEY_ORIGIN.as_bytes(), client_data.as_bytes(), b""]);
                [ssh_wire(&[algorithm, &p256_signature(key, &data)]), sk_trailer(*flags), after].concat()
            }
        };
        let mut envelope = b"SSHSIG".to_vec();
        envelope.extend(1u32.to_be_bytes());
        envelope.extend(ssh_wire(&[public, NAMESPACE.as_bytes(), b"", b"sha512", &blob]));
        envelope
    }
}

/// OpenSSH wire fields, each a length-prefixed string.
fn ssh_wire(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.extend(u32::try_from(field.len()).expect("field length").to_be_bytes());
        out.extend(*field);
    }
    out
}

/// What a token signs: the application's hash, the flags, the counter, the message's hash.
fn sk_data(application: &str, flags: u8, message_hash: &[u8]) -> Vec<u8> {
    [&Sha256::digest(application.as_bytes())[..], &[flags], &COUNTER.to_be_bytes(), message_hash].concat()
}

fn sk_trailer(flags: u8) -> Vec<u8> {
    [&[flags][..], &COUNTER.to_be_bytes()].concat()
}

fn p256_key(seed: u8) -> P256Key {
    P256Key::from_slice(&[seed; 32]).expect("p256 key")
}

fn p256_point(key: &P256Key) -> Vec<u8> {
    key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
}

fn sk_ecdsa_wire(key: &P256Key, application: &str) -> Vec<u8> {
    ssh_wire(&[b"sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256", &p256_point(key), application.as_bytes()])
}

/// An OpenSSH ECDSA signature: `r` and `s` as two `mpint`s.
fn p256_signature(key: &P256Key, data: &[u8]) -> Vec<u8> {
    let signature: p256::ecdsa::Signature = key.sign(data);
    let (r, s) = signature.split_bytes();
    ssh_wire(&[&mpint(&r), &mpint(&s)])
}

fn mpint(scalar: &[u8]) -> Vec<u8> {
    let start = scalar.iter().position(|byte| *byte != 0).unwrap_or(scalar.len());
    let mut out = scalar[start..].to_vec();
    if out.first().is_some_and(|byte| byte & 0x80 != 0) {
        out.insert(0, 0);
    }
    out
}
```

<a name="chunk-cast"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#cast`</sub>

```rust {#cast}
struct Cast {
    root: [TestKey; 4],
    online: TestKey,
    alice_laptop: TestKey,
    alice_token: TestKey,
    bob: TestKey,
    carol: TestKey,
}

impl Cast {
    fn new() -> Self {
        Self {
            root: [1, 2, 3, 4].map(|seed| TestKey::ed25519(seed, &format!("root-{seed}"), "fido2")),
            online: TestKey::ed25519(10, "ci", "software"),
            alice_laptop: TestKey::ed25519(20, "alice", "software"),
            alice_token: TestKey::ed25519(21, "alice", "fido2"),
            bob: TestKey::ed25519(22, "bob", "secure-enclave"),
            carol: TestKey::sshsig(23, "carol"),
        }
    }

    fn releasers(&self) -> Vec<&TestKey> {
        vec![&self.alice_laptop, &self.alice_token, &self.bob, &self.carol]
    }
}
```

The bodies are TUF's. The root gives every top-level role but `root` to
the online key or the releasers, and takes its root keys and signatory
rules from the vector. The top-level targets role delegates `fleet` and
`pilot`, each over the one pattern of its flat paths, `fleet/*` and
`pilot/*`, unless a vector widens `fleet`'s.

<a name="chunk-bodies"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#bodies`</sub>

```rust {#bodies}
fn listing(keys: &[&TestKey]) -> Value {
    Value::Object(keys.iter().map(|k| (k.id.clone(), k.object.clone())).collect::<Map<_, _>>())
}

fn ids(keys: &[&TestKey]) -> Vec<String> {
    keys.iter().map(|k| k.id.clone()).collect()
}

fn root_body(cast: &Cast, version: u64, root_keys: &[&TestKey], signatories: Value) -> Value {
    root_body_listing(cast, version, root_keys, &[], signatories)
}

/// A root that also lists `extra` keys, which no role names.
fn root_body_listing(cast: &Cast, version: u64, root_keys: &[&TestKey], extra: &[&TestKey], signatories: Value) -> Value {
    let releasers = cast.releasers();
    let mut all = root_keys.to_vec();
    all.push(&cast.online);
    all.extend(releasers.iter());
    all.extend(extra.iter());
    json!({
        "_type": "root", "spec_version": "1.0.37", "consistent_snapshot": false,
        "version": version, "expires": LATER, "keys": listing(&all),
        "roles": {
            "root": { "keyids": ids(root_keys), "threshold": 2 },
            "timestamp": { "keyids": [cast.online.id], "threshold": 1 },
            "snapshot": { "keyids": [cast.online.id], "threshold": 1 },
            "targets": { "keyids": ids(&releasers), "threshold": 1 },
        },
        "x-release-metadata-signatories": signatories,
    })
}

fn top_targets(keys: &[&TestKey], fleet_threshold: u64) -> Value {
    top_targets_with_fleet_paths(keys, fleet_threshold, &["fleet/*"])
}

fn top_targets_with_fleet_paths(keys: &[&TestKey], fleet_threshold: u64, fleet_paths: &[&str]) -> Value {
    json!({
        "_type": "targets", "spec_version": "1.0.37", "version": 1, "expires": LATER,
        "targets": {},
        "delegations": {
            "keys": listing(keys),
            "roles": [
                { "name": "fleet", "keyids": ids(keys), "threshold": fleet_threshold,
                  "terminating": true, "paths": fleet_paths },
                { "name": "pilot", "keyids": ids(keys), "threshold": 1,
                  "terminating": true, "paths": ["pilot/*"] },
            ],
        },
    })
}

/// A root whose every key uses TUF's own `ed25519` scheme and whose
/// signatories each hold one key, so a stock TUF client and this verifier
/// count alike. Its key objects and its signatory rules still carry the
/// `x-release-metadata-` fields.
fn tuf_root(cast: &Cast, version: u64, root_keys: &[&TestKey]) -> Value {
    let releasers = [&cast.alice_laptop, &cast.bob];
    let mut root = root_body(cast, version, root_keys, json!({ "alice": { "keys_required": 1 } }));
    let mut all = root_keys.to_vec();
    all.extend([&cast.online, &cast.alice_laptop, &cast.bob]);
    root["keys"] = listing(&all);
    root["roles"]["targets"] = json!({ "keyids": ids(&releasers), "threshold": 1 });
    root
}

fn audience(paths: &[&str]) -> Value {
    let entry = json!({
        "length": ARTIFACT.len(),
        "hashes": {
            "sha256": hex::encode(Sha256::digest(ARTIFACT)),
            "sha512": hex::encode(Sha512::digest(ARTIFACT)),
        },
    });
    let targets: Map<String, Value> = paths.iter().map(|p| ((*p).to_owned(), entry.clone())).collect();
    json!({ "_type": "targets", "spec_version": "1.0.37", "version": 1, "expires": LATER, "targets": targets })
}

/// One delegation entry: `threshold` signatories of `keys` sign `name`'s file, for `paths`.
fn delegated_role(name: &str, keys: &[&TestKey], threshold: u64, paths: &[&str]) -> Value {
    json!({ "name": name, "keyids": ids(keys), "threshold": threshold, "terminating": true, "paths": paths })
}

/// A targets file that lists `entries` and delegates `roles` to `keys`, expiring at `expires`.
fn delegating(entries: &[&str], keys: &[&TestKey], roles: Vec<Value>, expires: &str) -> Value {
    let mut body = audience(entries);
    body["expires"] = json!(expires);
    body["delegations"] = json!({ "keys": listing(keys), "roles": roles });
    body
}

/// A trusted root that marks the `public` audience public (decision §8).
fn root_marking_public(cast: &Cast) -> Value {
    let root_keys = [&cast.root[0], &cast.root[1]];
    let mut body = root_body(cast, 1, &root_keys, json!({}));
    body["x-release-metadata-public-audiences"] = json!(["public"]);
    signed(body, &root_keys)
}

fn meta(version: u64, bytes: &[u8]) -> Value {
    json!({ "version": version, "length": bytes.len(), "hashes": { "sha256": hex::encode(Sha256::digest(bytes)) } })
}
```

A vector starts from a baseline repository that verifies, and changes one
thing. The baseline: root version 1 with two root keys, a top-level
targets role that delegates both audiences at a threshold of one, and a
`fleet` role that lists the artifact, each signed by Alice's laptop key.

<a name="chunk-parts"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#parts`</sub>

```rust {#parts}
struct Parts {
    trusted_root: Value,
    roots: Vec<(u64, Value)>,
    trusted_timestamp_version: Option<u64>,
    targets: Value,
    fleet: Value,
    pilot: Value,
    /// Further targets files, by role name.
    extra: Vec<(&'static str, Value)>,
    timestamp_version: u64,
    timestamp_expires: &'static str,
    path: &'static str,
}

impl Parts {
    fn base(cast: &Cast) -> Self {
        let root_keys = [&cast.root[0], &cast.root[1]];
        Self {
            trusted_root: signed(root_body(cast, 1, &root_keys, json!({})), &root_keys),
            roots: Vec::new(),
            trusted_timestamp_version: None,
            targets: signed(top_targets(&cast.releasers(), 1), &[&cast.alice_laptop]),
            fleet: signed(audience(&[FLEET_PATH]), &[&cast.alice_laptop]),
            pilot: signed(audience(&[]), &[&cast.alice_laptop]),
            extra: Vec::new(),
            timestamp_version: 1,
            timestamp_expires: LATER,
            path: FLEET_PATH,
        }
    }
}

struct Vector {
    name: &'static str,
    decision: &'static str,
    claim: &'static str,
    expect: Value,
    parts: Parts,
}

fn verified(role: &str) -> Value {
    json!({ "verified": { "role": role } })
}

fn refused(role: &str, rule: &str) -> Value {
    json!({ "refused": { "role": role, "rule": rule } })
}
```

Writing a vector computes the snapshot over the targets files as written,
and the timestamp over the snapshot, so the listings always match the
bytes on disk.

<a name="chunk-write-vector"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#write-vector`</sub>

```rust {#write-vector}
fn bytes(value: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec_pretty(value).expect("json");
    out.push(b'\n');
    out
}

fn timestamp(cast: &Cast, version: u64, expires: &str, snapshot: &[u8]) -> Value {
    let body = json!({
        "_type": "timestamp", "spec_version": "1.0.37", "version": version, "expires": expires,
        "meta": { "snapshot.json": meta(1, snapshot) },
    });
    signed(body, &[&cast.online])
}

fn write(out: &Path, cast: &Cast, vector: Vector) {
    let dir = out.join(vector.name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("trusted")).expect("trusted directory");
    fs::create_dir_all(dir.join("fetched")).expect("fetched directory");
    let put = |path: &str, value: &Value| fs::write(dir.join(path), bytes(value)).expect("write");
    let parts = vector.parts;
    put("trusted/root.json", &parts.trusted_root);
    for (version, root) in &parts.roots {
        put(&format!("fetched/{version}.root.json"), root);
    }
    let mut snapshot_meta = Map::new();
    let named = [("targets", &parts.targets), ("fleet", &parts.fleet), ("pilot", &parts.pilot)];
    for (role, file) in named.into_iter().chain(parts.extra.iter().map(|(role, file)| (*role, file))) {
        put(&format!("fetched/{role}.json"), file);
        snapshot_meta.insert(format!("{role}.json"), meta(1, &bytes(file)));
    }
    let snapshot_body = json!({
        "_type": "snapshot", "spec_version": "1.0.37", "version": 1, "expires": LATER,
        "meta": snapshot_meta,
    });
    let snapshot = bytes(&signed(snapshot_body, &[&cast.online]));
    fs::write(dir.join("fetched/snapshot.json"), &snapshot).expect("write snapshot");
    put("fetched/timestamp.json", &timestamp(cast, parts.timestamp_version, parts.timestamp_expires, &snapshot));
    if let Some(version) = parts.trusted_timestamp_version {
        put("trusted/timestamp.json", &timestamp(cast, version, LATER, &snapshot));
    }
    put("case.json", &json!({
        "decision": vector.decision,
        "claim": vector.claim,
        "now": NOW,
        "target": {
            "path": parts.path,
            "length": ARTIFACT.len(),
            "hashes": { "sha256": hex::encode(Sha256::digest(ARTIFACT)) },
        },
        "expect": vector.expect,
    }));
}
```

The cases follow the claims table. Each changes the baseline in one place.

<a name="chunk-vector-cases"></a><sub>[`tests/conformance/main.rs`](../../crates/x0k-release-metadata/tests/conformance/main.rs) · `#vector-cases`</sub>

```rust {#vector-cases}
fn vectors(c: &Cast) -> Vec<Vector> {
    let r = &c.root;
    let releasers = c.releasers();
    let fleet_by = |signers: &[&TestKey]| signed(audience(&[FLEET_PATH]), signers);
    let targets_at_two = signed(top_targets(&releasers, 2), &[&c.alice_laptop]);
    let targets_at_two_by_bob = signed(top_targets(&releasers, 2), &[&c.bob]);
    let alice_needs_two = json!({ "alice": { "keys_required": 2 } });
    let dave = TestKey::ed25519(22, "dave", "software");
    let mut with_dave = releasers.clone();
    with_dave.push(&dave);
    let three_root_keys = [&r[0], &r[1], &r[2]];
    let carol_as_hex = TestKey::ed25519(23, "erin", "software");
    let carol_with_comment = TestKey::sshsig_line(23, |line| format!("{line} carol@laptop")).named("carol", "software");
    let with_commented_carol = [&c.alice_laptop, &c.alice_token, &c.bob, &carol_with_comment];
    let plain = [TestKey::plain(30), TestKey::plain(31)];
    let plain_keys = [&plain[0], &plain[1]];
    let session = TestKey::ed25519(40, "session", "software");
    let advance = |pattern: &str, expires: &str| {
        delegating(&[], &[&session], vec![delegated_role("chariot-1.1", &[&session], 1, &[pattern])], expires)
    };
    let session_file = |paths: &[&str]| ("chariot-1.1", signed(audience(paths), &[&session]));
    let audiences = vec![
        delegated_role("fleet", &releasers, 1, &["fleet/*"]),
        delegated_role("pilot", &releasers, 1, &["pilot/*"]),
        delegated_role("public", &releasers, 1, &["public/*"]),
    ];
    let with_public = signed(delegating(&[], &releasers, audiences, LATER), &[&c.alice_laptop]);
    let public_advance_by = |signers: &[&TestKey]| ("public", signed(advance("public/chariot-1.1-*", SOON), signers));
    let frank = TestKey::enclave(50, "frank");
    let dave_touched = TestKey::token_ed25519(51, "dave", 0x01);
    let dave_untouched = TestKey::token_ed25519(51, "dave", 0x00);
    let erin = TestKey::token_ecdsa(52, "erin", 0x01);
    let grace = TestKey::passkey(53, "grace", None);
    let grace_elsewhere = TestKey::passkey(53, "grace", Some(&b"another message"[..]));
    let listing_only = |key: &TestKey| signed(top_targets(&[key], 1), &[&c.alice_laptop]);
    let root_ruling = |rules: Value| signed(root_body(c, 1, &[&r[0], &r[1]], rules), &[&r[0], &r[1]]);
    let dave_needs_touch = json!({ "dave": { "flags": ["user-present"] } });
    let tuf_releasers = [&c.alice_laptop, &c.bob];
    let tuf_base = || Parts {
        trusted_root: signed(tuf_root(c, 1, &[&r[0], &r[1]]), &[&r[0], &r[1]]),
        targets: signed(top_targets(&tuf_releasers, 1), &[&c.alice_laptop]),
        ..Parts::base(c)
    };
    let root_with = |extra: &[&TestKey]| signed(root_body_listing(c, 1, &[&r[0], &r[1]], extra, json!({})), &[&r[0], &r[1]]);
    vec![
        Vector {
            name: "s1-baseline-verifies", decision: "§1",
            claim: "A target that a delegated role lists, with every file signed, current and consistent, verifies.",
            expect: verified("fleet"), parts: Parts::base(c),
        },
        Vector {
            name: "s1-lower-timestamp-version", decision: "§1",
            claim: "A timestamp lower than the trusted one is refused as a rollback.",
            expect: refused("timestamp", "rollback"),
            parts: Parts { trusted_timestamp_version: Some(5), timestamp_version: 4, ..Parts::base(c) },
        },
        Vector {
            name: "s1-expired-timestamp", decision: "§1",
            claim: "An expired timestamp is refused.",
            expect: refused("timestamp", "expired"),
            parts: Parts { timestamp_expires: PAST, ..Parts::base(c) },
        },
        Vector {
            name: "s2-fleet-artifact-looked-up-for-pilot", decision: "§2",
            claim: "An artifact signed for fleet is refused when looked up for pilot, even when the fleet role lists the pilot path.",
            expect: refused("targets", "unknown-target"),
            parts: Parts {
                fleet: signed(audience(&[FLEET_PATH, PILOT_PATH]), &[&c.alice_laptop]),
                path: PILOT_PATH,
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s2-path-two-levels-under-audience", decision: "§2",
            claim: "A path two levels under an audience is refused as unknown, even when the delegation's patterns cover it and the audience role lists it.",
            expect: refused("targets", "unknown-target"),
            parts: Parts {
                targets: signed(top_targets_with_fleet_paths(&releasers, 1, &["fleet/*", "fleet/*/*"]), &[&c.alice_laptop]),
                fleet: signed(audience(&[DEEP_FLEET_PATH]), &[&c.alice_laptop]),
                path: DEEP_FLEET_PATH,
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s3-sshsig-verifies", decision: "§3",
            claim: "An SSHSIG signature under the namespace release-metadata counts.",
            expect: verified("fleet"),
            parts: Parts { fleet: fleet_by(&[&c.carol]), ..Parts::base(c) },
        },
        Vector {
            name: "s3-sshsig-wrong-namespace", decision: "§3",
            claim: "An SSHSIG signature under another namespace does not count.",
            expect: refused("fleet", "threshold"),
            parts: Parts { fleet: fleet_by(&[&c.carol.under_namespace("git")]), ..Parts::base(c) },
        },
        Vector {
            name: "s3-sshsig-key-line-with-comment", decision: "§3",
            claim: "An SSHSIG key whose line carries a comment is malformed, and its signature does not count.",
            expect: refused("fleet", "threshold"),
            parts: Parts {
                targets: signed(top_targets(&with_commented_carol, 1), &[&c.alice_laptop]),
                fleet: fleet_by(&[&carol_with_comment]),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s4-one-signatory-two-keys", decision: "§4",
            claim: "One signatory signing with two keys does not meet a threshold of two.",
            expect: refused("fleet", "threshold"),
            parts: Parts {
                targets: targets_at_two.clone(),
                fleet: fleet_by(&[&c.alice_laptop, &c.alice_token]),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s4-two-signatories-meet-two", decision: "§4",
            claim: "Two signatories with one key each meet a threshold of two.",
            expect: verified("fleet"),
            parts: Parts {
                targets: targets_at_two.clone(),
                fleet: fleet_by(&[&c.alice_laptop, &c.bob]),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s4-signatory-rule-unmet", decision: "§4",
            claim: "A signatory whose rule requires two keys does not count with one.",
            expect: refused("fleet", "threshold"),
            parts: Parts {
                trusted_root: signed(root_body(c, 1, &[&r[0], &r[1]], alice_needs_two.clone()), &[&r[0], &r[1]]),
                targets: targets_at_two_by_bob.clone(),
                fleet: fleet_by(&[&c.alice_laptop, &c.bob]),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s4-signatory-rule-met", decision: "§4",
            claim: "A signatory whose rule requires two keys counts with two.",
            expect: verified("fleet"),
            parts: Parts {
                trusted_root: signed(root_body(c, 1, &[&r[0], &r[1]], alice_needs_two), &[&r[0], &r[1]]),
                targets: targets_at_two_by_bob,
                fleet: fleet_by(&[&c.alice_laptop, &c.alice_token, &c.bob]),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s4-one-key-two-signatories", decision: "§4",
            claim: "One public key listed under two signatories in a delegation is refused.",
            expect: refused("targets", "malformed"),
            parts: Parts {
                targets: signed(top_targets(&with_dave, 2), &[&c.alice_laptop]),
                fleet: fleet_by(&[&c.bob, &dave]),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s4-root-lists-one-key-twice", decision: "§4",
            claim: "A root that lists one public key under two signatories is refused as root, before any release is read.",
            expect: refused("root", "malformed"),
            parts: Parts { trusted_root: root_with(&[&dave]), ..Parts::base(c) },
        },
        Vector {
            name: "s4-one-key-in-two-forms", decision: "§4",
            claim: "A root that lists one Ed25519 key in TUF's hex form and again as an SSH key line is refused.",
            expect: refused("root", "malformed"),
            parts: Parts { trusted_root: root_with(&[&carol_as_hex]), ..Parts::base(c) },
        },
        Vector {
            name: "s4-unnamed-keys-count-as-tuf", decision: "§4",
            claim: "Keys that name no signatory are each their own signatory, so two of them meet a threshold of two.",
            expect: verified("fleet"),
            parts: Parts {
                targets: signed(top_targets(&plain_keys, 2), &[&c.alice_laptop]),
                fleet: signed(audience(&[FLEET_PATH]), &plain_keys),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s5-rotation", decision: "§5",
            claim: "A root that rotates its keys verifies when the old and the new thresholds both sign it.",
            expect: verified("fleet"),
            parts: Parts {
                roots: vec![(2, signed(root_body(c, 2, &[&r[1], &r[2]], json!({})), &[&r[0], &r[1], &r[2]]))],
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s5-removed-key", decision: "§5",
            claim: "A key that a root removed does not count toward the next root, even in a root that adds it back.",
            expect: refused("root", "root-threshold"),
            parts: Parts {
                trusted_root: signed(root_body(c, 1, &three_root_keys, json!({})), &three_root_keys),
                roots: vec![
                    (2, signed(root_body(c, 2, &[&r[1], &r[2]], json!({})), &three_root_keys)),
                    (3, signed(root_body(c, 3, &[&r[0], &r[1]], json!({})), &[&r[0], &r[1]])),
                ],
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s5-new-keys-only", decision: "§5",
            claim: "A root signed only by its new keys is refused.",
            expect: refused("root", "root-threshold"),
            parts: Parts {
                roots: vec![(2, signed(root_body(c, 2, &[&r[2], &r[3]], json!({})), &[&r[2], &r[3]]))],
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s5-new-root-without-its-keys", decision: "§5",
            claim: "A root signed only by the old keys, not by its own, is refused.",
            expect: refused("root", "root-threshold"),
            parts: Parts {
                roots: vec![(2, signed(root_body(c, 2, &[&r[2], &r[3]], json!({})), &[&r[0], &r[1]]))],
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s5-root-skips-version", decision: "§5",
            claim: "A root that skips a version is refused.",
            expect: refused("root", "root-sequence"),
            parts: Parts {
                roots: vec![(3, signed(root_body(c, 3, &[&r[0], &r[1]], json!({})), &[&r[0], &r[1]]))],
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s6-targets-signed-only-by-online-key", decision: "§6",
            claim: "Targets metadata that only the online key signed is refused: the key on the build server signs freshness, never a release.",
            expect: refused("targets", "threshold"),
            parts: Parts { targets: signed(top_targets(&releasers, 1), &[&c.online]), ..Parts::base(c) },
        },
        Vector {
            name: "s3-software-enclave-verifies", decision: "§3",
            claim: "A P-256 SSHSIG signature, the kind a Secure Enclave key makes through Secretive, counts (software-made).",
            expect: verified("fleet"),
            parts: Parts { targets: listing_only(&frank), fleet: fleet_by(&[&frank]), ..Parts::base(c) },
        },
        Vector {
            name: "s3-software-fido2-ed25519-verifies", decision: "§3",
            claim: "An sk-ssh-ed25519 signature over the U2F blob, with its flags and counter, counts (software-made).",
            expect: verified("fleet"),
            parts: Parts { targets: listing_only(&dave_touched), fleet: fleet_by(&[&dave_touched]), ..Parts::base(c) },
        },
        Vector {
            name: "s3-software-fido2-ecdsa-verifies", decision: "§3",
            claim: "An sk-ecdsa-sha2-nistp256 signature over the U2F blob counts (software-made).",
            expect: verified("fleet"),
            parts: Parts { targets: listing_only(&erin), fleet: fleet_by(&[&erin]), ..Parts::base(c) },
        },
        Vector {
            name: "s3-software-passkey-verifies", decision: "§3",
            claim: "A webauthn-sk-ecdsa-sha2-nistp256 signature, whose client data carries the SSHSIG blob as its challenge, counts (software-made).",
            expect: verified("fleet"),
            parts: Parts { targets: listing_only(&grace), fleet: fleet_by(&[&grace]), ..Parts::base(c) },
        },
        Vector {
            name: "s3-software-passkey-other-challenge", decision: "§3",
            claim: "A WebAuthn signature whose client data carries another challenge does not count, though the authenticator signed it (software-made).",
            expect: refused("fleet", "threshold"),
            parts: Parts { targets: listing_only(&grace), fleet: fleet_by(&[&grace_elsewhere]), ..Parts::base(c) },
        },
        Vector {
            name: "s4-software-touch-missing", decision: "§4",
            claim: "A token signature without the touch flag does not count for a signatory whose rule demands one (software-made).",
            expect: refused("fleet", "threshold"),
            parts: Parts {
                trusted_root: root_ruling(dave_needs_touch.clone()),
                targets: listing_only(&dave_untouched),
                fleet: fleet_by(&[&dave_untouched]),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s4-software-touch-present", decision: "§4",
            claim: "The same token's signature with the touch flag counts (software-made).",
            expect: verified("fleet"),
            parts: Parts {
                trusted_root: root_ruling(dave_needs_touch),
                targets: listing_only(&dave_touched),
                fleet: fleet_by(&[&dave_touched]),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s4-presence-rule-on-non-sk-key", decision: "§4",
            claim: "A root whose presence rule names a signatory holding a key that is not an sk key is refused, before any release is read.",
            expect: refused("root", "malformed"),
            parts: Parts {
                trusted_root: root_ruling(json!({ "alice": { "flags": ["user-present"] } })),
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s8-advance-delegation-verifies", decision: "§8",
            claim: "A target that a session key signs, under a delegation of its version's files that the audience's signatories made for less than a day, verifies.",
            expect: verified("chariot-1.1"),
            parts: Parts {
                fleet: signed(advance("fleet/chariot-1.1-*", SOON), &[&c.alice_laptop]),
                extra: vec![session_file(&[ADVANCE_PATH, OTHER_VERSION_PATH])],
                path: ADVANCE_PATH,
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s8-advance-delegation-other-version", decision: "§8",
            claim: "A target for another version is refused, even when the session key signs it.",
            expect: refused("targets", "unknown-target"),
            parts: Parts {
                fleet: signed(advance("fleet/chariot-1.1-*", SOON), &[&c.alice_laptop]),
                extra: vec![session_file(&[ADVANCE_PATH, OTHER_VERSION_PATH])],
                path: OTHER_VERSION_PATH,
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s8-advance-delegation-expired", decision: "§8",
            claim: "A target under a delegation whose metadata has expired is refused.",
            expect: refused("fleet", "expired"),
            parts: Parts {
                fleet: signed(advance("fleet/chariot-1.1-*", JUST_PAST), &[&c.alice_laptop]),
                extra: vec![session_file(&[ADVANCE_PATH])],
                path: ADVANCE_PATH,
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s8-public-delegation-missing-signatory", decision: "§8",
            claim: "A delegation for an audience the root marks public, signed by two of its role's three signatories, is refused.",
            expect: refused("public", "public-delegation"),
            parts: Parts {
                trusted_root: root_marking_public(c),
                targets: with_public.clone(),
                extra: vec![public_advance_by(&[&c.alice_laptop, &c.bob]), session_file(&[PUBLIC_ADVANCE_PATH])],
                path: PUBLIC_ADVANCE_PATH,
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s8-public-delegation-every-signatory", decision: "§8",
            claim: "That delegation, signed by every signatory its role lists, verifies.",
            expect: verified("chariot-1.1"),
            parts: Parts {
                trusted_root: root_marking_public(c),
                targets: with_public.clone(),
                extra: vec![public_advance_by(&[&c.alice_laptop, &c.bob, &c.carol]), session_file(&[PUBLIC_ADVANCE_PATH])],
                path: PUBLIC_ADVANCE_PATH,
                ..Parts::base(c)
            },
        },
        Vector {
            name: "s8-public-release-meets-its-threshold", decision: "§8",
            claim: "A release in a public audience whose file delegates nothing still needs only its role's threshold.",
            expect: verified("public"),
            parts: Parts {
                trusted_root: root_marking_public(c),
                targets: with_public,
                extra: vec![("public", signed(audience(&[PUBLIC_PATH]), &[&c.alice_laptop]))],
                path: PUBLIC_PATH,
                ..Parts::base(c)
            },
        },
        Vector {
            name: "tuf-baseline-verifies", decision: "§4",
            claim: "A TUF-native repository, whose keys and root still carry the extension fields, verifies (stock clients agree).",
            expect: verified("fleet"), parts: tuf_base(),
        },
        Vector {
            name: "tuf-expired-timestamp", decision: "§1",
            claim: "Its expired timestamp is refused (stock clients agree).",
            expect: refused("timestamp", "expired"),
            parts: Parts { timestamp_expires: PAST, ..tuf_base() },
        },
        Vector {
            name: "tuf-lower-timestamp-version", decision: "§1",
            claim: "Its timestamp lower than the trusted one is refused (stock clients agree).",
            expect: refused("timestamp", "rollback"),
            parts: Parts { trusted_timestamp_version: Some(5), timestamp_version: 4, ..tuf_base() },
        },
        Vector {
            name: "tuf-fleet-artifact-looked-up-for-pilot", decision: "§2",
            claim: "Its fleet artifact looked up for pilot is refused (stock clients agree).",
            expect: refused("targets", "unknown-target"),
            parts: Parts {
                fleet: signed(audience(&[FLEET_PATH, PILOT_PATH]), &[&c.alice_laptop]),
                path: PILOT_PATH,
                ..tuf_base()
            },
        },
        Vector {
            name: "tuf-threshold-unmet", decision: "§4",
            claim: "One signature where its role needs two is refused (stock clients agree).",
            expect: refused("fleet", "threshold"),
            parts: Parts { targets: signed(top_targets(&tuf_releasers, 2), &[&c.alice_laptop]), ..tuf_base() },
        },
        Vector {
            name: "tuf-rotation-verifies", decision: "§5",
            claim: "Its root rotation signed by both thresholds verifies (stock clients agree).",
            expect: verified("fleet"),
            parts: Parts {
                roots: vec![(2, signed(tuf_root(c, 2, &[&r[1], &r[2]]), &[&r[0], &r[1], &r[2]]))],
                ..tuf_base()
            },
        },
        Vector {
            name: "tuf-new-keys-only", decision: "§5",
            claim: "Its root signed only by the new keys is refused (stock clients agree).",
            expect: refused("root", "root-threshold"),
            parts: Parts {
                roots: vec![(2, signed(tuf_root(c, 2, &[&r[2], &r[3]]), &[&r[2], &r[3]]))],
                ..tuf_base()
            },
        },
    ]
}
```

The vectors pin the outcomes a reader relies on: which update verifies and
which is refused, by which role and rule. They do not pin the wording of a
refusal or the order of verdicts, which may change freely. What they leave
open is the hardware half of §3 and §4. A vector whose envelope a FIDO2
token made, and one whose touch flag is missing, need the operator's token
to sign them once.

## Stock TUF clients

Decision §4 says that a standard TUF client reads a repository the way
this verifier does when every key uses TUF's own schemes and each
signatory holds one key per role, even though the key objects and the
root carry the `x-release-metadata-` fields. The `tuf-` vectors are such
repositories, and the interop check runs each of them through two stock
clients, python-tuf and go-tuf, and compares their verdicts with the
vector's. A client's verdict is "verified" when its update succeeds and
it finds the target with the vector's length and hashes, and "refused"
otherwise. The rule a client names is its own, so only the verdict is
compared.

Each client fetches the vector's `fetched/` directory as its repository,
through a fetcher that answers 404 for a missing file, and starts from
`trusted/root.json` and, where the vector has one, `trusted/timestamp.json`.
The clients read the clock themselves, so the check holds while the
vectors' expiry, 2030, lies ahead. One kind of vector is left out on
purpose: a root that skips a version. A stock client asks for root
version N+1 by name and stops at the first one missing, so it never sees
a version N+2 that the embedder of this verifier would hand it; that
difference is in the fetching, not in the format.

The check lives in the crate's `interop/` directory and is not part of
the crate's package. `interop/run.sh` runs it, given python3 with the
`tuf` package and go; on a machine with nix:

```sh
nix shell nixpkgs#go --command bash -c 'PATH=$(nix build --no-link --print-out-paths --impure --expr "(import (builtins.getFlake \"nixpkgs\") {}).python3.withPackages (p: [ p.tuf ])")/bin:$PATH bash interop/run.sh'
```

It exits non-zero when either client disagrees with a vector. The
python-tuf harness is a test harness only, run by that script; nothing in
the crate depends on it.

<a name="chunk-interop-python"></a><sub>[`interop/tuf_client_verdicts.py`](../../crates/x0k-release-metadata/interop/tuf_client_verdicts.py) · `#interop-python`</sub>

```python {#interop-python file="interop/tuf_client_verdicts.py"}
"""Runs TUF-native conformance vectors through python-tuf and prints each verdict.

A test harness for x0k-release-metadata's interop check; interop/run.sh runs it.
Usage: python3 tuf_client_verdicts.py <vectors dir> <vector name>...
Prints one line per vector: `<name> agree|DISAGREE expected=<v> got=<v> <detail>`.
"""

import json
import os
import shutil
import sys
import tempfile

from tuf.api.exceptions import DownloadHTTPError
from tuf.ngclient import Updater
from tuf.ngclient.fetcher import FetcherInterface


class DirectoryFetcher(FetcherInterface):
    """Serves a vector's fetched/ directory as the repository."""

    def __init__(self, directory):
        self.directory = directory

    def _fetch(self, url):
        name = url.rsplit("/", 1)[-1]
        path = os.path.join(self.directory, name)
        if not os.path.isfile(path):
            raise DownloadHTTPError(f"{name} is not in the vector", 404)
        with open(path, "rb") as file:
            return iter([file.read()])


def verdict(vector):
    with open(os.path.join(vector, "case.json")) as file:
        case = json.load(file)
    target = case["target"]
    with tempfile.TemporaryDirectory() as local:
        for name in ["root.json", "timestamp.json"]:
            trusted = os.path.join(vector, "trusted", name)
            if os.path.exists(trusted):
                shutil.copy(trusted, local)
        try:
            updater = Updater(
                metadata_dir=local,
                metadata_base_url="https://vector.invalid/",
                target_dir=local,
                target_base_url="https://vector.invalid/targets/",
                fetcher=DirectoryFetcher(os.path.join(vector, "fetched")),
            )
            updater.refresh()
            info = updater.get_targetinfo(target["path"])
        except Exception as error:  # every refusal a client raises is a refused verdict
            return next(iter(case["expect"])), "refused", type(error).__name__
    if info is None:
        return next(iter(case["expect"])), "refused", "no such target"
    if info.length != target["length"] or any(info.hashes.get(a) != h for a, h in target["hashes"].items()):
        return next(iter(case["expect"])), "refused", "length or hash differs"
    return next(iter(case["expect"])), "verified", ""


def main():
    vectors, names = sys.argv[1], sys.argv[2:]
    for name in names:
        expected, got, detail = verdict(os.path.join(vectors, name))
        agreement = "agree" if expected == got else "DISAGREE"
        print(f"{name} {agreement} expected={expected} got={got} {detail}".rstrip())


if __name__ == "__main__":
    main()
```

<a name="chunk-interop-go"></a><sub>[`interop/go-tuf/main.go`](../../crates/x0k-release-metadata/interop/go-tuf/main.go) · `#interop-go`</sub>

```go {#interop-go file="interop/go-tuf/main.go"}
// Runs TUF-native conformance vectors through go-tuf and prints each verdict.
//
// A test harness for x0k-release-metadata's interop check; interop/run.sh runs it.
// Usage: go run . <vectors dir> <vector name>...
// Prints one line per vector: `<name> agree|DISAGREE expected=<v> got=<v> <detail>`.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// directoryFetcher serves a vector's fetched/ directory as the repository.
type directoryFetcher struct{ dir string }

func (f directoryFetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(f.dir, path.Base(urlPath)))
	if err != nil {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: 404, URL: urlPath}
	}
	return data, nil
}

type vectorCase struct {
	Target struct {
		Path   string            `json:"path"`
		Length int64             `json:"length"`
		Hashes map[string]string `json:"hashes"`
	} `json:"target"`
	Expect map[string]json.RawMessage `json:"expect"`
}

func verdict(dir string) (string, string, string) {
	raw, err := os.ReadFile(filepath.Join(dir, "case.json"))
	if err != nil {
		return "?", "refused", err.Error()
	}
	var c vectorCase
	if err := json.Unmarshal(raw, &c); err != nil {
		return "?", "refused", err.Error()
	}
	expected := "?"
	for key := range c.Expect {
		expected = key
	}
	local, err := os.MkdirTemp("", "go-tuf-vector")
	if err != nil {
		return expected, "refused", err.Error()
	}
	defer os.RemoveAll(local)
	root, err := os.ReadFile(filepath.Join(dir, "trusted", "root.json"))
	if err != nil {
		return expected, "refused", err.Error()
	}
	for _, name := range []string{"root.json", "timestamp.json"} {
		if data, err := os.ReadFile(filepath.Join(dir, "trusted", name)); err == nil {
			_ = os.WriteFile(filepath.Join(local, name), data, 0o644)
		}
	}
	cfg, err := config.New("https://vector.invalid/", root)
	if err != nil {
		return expected, "refused", err.Error()
	}
	cfg.Fetcher = directoryFetcher{dir: filepath.Join(dir, "fetched")}
	cfg.LocalMetadataDir = local
	cfg.LocalTargetsDir = local
	up, err := updater.New(cfg)
	if err != nil {
		return expected, "refused", oneLine(err)
	}
	if err := up.Refresh(); err != nil {
		return expected, "refused", oneLine(err)
	}
	info, err := up.GetTargetInfo(c.Target.Path)
	if err != nil {
		return expected, "refused", oneLine(err)
	}
	if info.Length != c.Target.Length {
		return expected, "refused", "length differs"
	}
	for algorithm, want := range c.Target.Hashes {
		if hex.EncodeToString([]byte(info.Hashes[algorithm])) != want {
			return expected, "refused", "hash differs"
		}
	}
	return expected, "verified", ""
}

func oneLine(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

func main() {
	vectors, names := os.Args[1], os.Args[2:]
	for _, name := range names {
		expected, got, detail := verdict(filepath.Join(vectors, name))
		agreement := "agree"
		if expected != got {
			agreement = "DISAGREE"
		}
		fmt.Println(strings.TrimSpace(fmt.Sprintf("%s %s expected=%s got=%s %s", name, agreement, expected, got, detail)))
	}
}
```

The script writes the Go module file into a scratch directory, pinning
go-tuf's version, and `go mod tidy` resolves the rest there, checked
against Go's checksum database.

<a name="chunk-interop-run"></a><sub>[`interop/run.sh`](../../crates/x0k-release-metadata/interop/run.sh) · `#interop-run`</sub>

```bash {#interop-run file="interop/run.sh"}
#!/usr/bin/env bash
# Runs the TUF-native conformance vectors (vectors/tuf-*) through python-tuf
# and go-tuf, and fails when either client's verdict differs from a vector's.
#
#   bash interop/run.sh [vectors dir]
#
# Needs python3 with the tuf package, and go; see the vectors chapter for the
# nix command.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
vectors=$(cd "${1:-$here/../vectors}" && pwd)
names=()
for dir in "$vectors"/tuf-*/; do
  names+=("$(basename "$dir")")
done
[ ${#names[@]} -gt 0 ] || { echo "no tuf-* vectors under $vectors" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here/go-tuf/main.go" "$work/"
printf 'module interop\n\ngo 1.24\n\nrequire github.com/theupdateframework/go-tuf/v2 v2.4.2\n' > "$work/go.mod"
python3 "$here/tuf_client_verdicts.py" "$vectors" "${names[@]}" | sed 's/^/python-tuf /' > "$work/verdicts"
(cd "$work" && go mod tidy >/dev/null 2>&1 && go run . "$vectors" "${names[@]}") | sed 's/^/go-tuf /' >> "$work/verdicts"
cat "$work/verdicts"
[ "$(grep -c ' agree ' "$work/verdicts")" -eq $(( 2 * ${#names[@]} )) ] || { echo "a stock client disagrees with a vector" >&2; exit 1; }
```
