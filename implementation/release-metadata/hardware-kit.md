# The hardware signing kit of x0k-release-metadata

```turtle folio:document
implementation:release-metadata\/hardware-kit a x0k:Implementation ;
    x0k:status "draft" ;
    x0k:summary "The kit an operator runs once on a Mac to make one conformance vector per hardware scheme, signed by the real signer: fresh FIDO2 keys through ssh-keygen, a fresh Secure Enclave key through Secretive, and a passkey through a local WebAuthn page, each signed through the crate's own ceremony, one file at a time or two files with one batch signature." ;
    x0k:concerns "trust", "signing", "keys", "conformance", "ceremony" ;
    x0k:cites implementation:release-metadata\/release-metadata,
        implementation:release-metadata\/vectors,
        implementation:release-metadata\/ceremony ;
    x0k:implements design:distribution-and-updates ;
    x0k:motivatedBy architecture:release-metadata ;
    folio:tangleCrate "crates/x0k-release-metadata" ;
    folio:tangleRoot "examples/hardware_kit.rs" .
```

Decision `x0k:architecture/release-metadata` §3 is checked by one
conformance vector per scheme, "each signature made by the real signer".
The generator (`implementation:release-metadata/vectors`) can only stand
in for a Secure Enclave, a FIDO2 token or a passkey with a software key.
A vector signed by the device itself needs the device and a person to
touch it, so it is made once, on the operator's Mac, by this kit. The
vectors it writes are named `hw-<scheme>`, and they join the others under
`vectors/` when the operator copies them back.

The kit makes fresh keys only. It never reads `~/.ssh`, and it refuses a
Secretive key that is the agent's `chariot-root` key, which signs real
chariot releases. Each vector is signed through the crate's own ceremony:
`stage`, then `sign` with the device's signer program, then `status`, so
the kit also shows the ceremony working with each real signer. The
ceremony's `sign` checks each new signature with the verifier before it
writes it, so a signature this crate cannot verify stops the kit there.

## What a hardware vector holds

A hardware vector is a small repository like every other vector. Its
root's keys, its top-level targets key and its online key are software
keys with fixed seeds, as the generator's are. The top-level targets role
delegates `fleet/*` to the one hardware key, for a signatory named
`operator`. For a FIDO2 token, the root also gives `operator` the rule
`user-present`, so the vector proves that the token's real signature
carries the touch flag. The `fleet` file lists one artifact, and the
hardware key signs it.

<a name="chunk-kit"></a><sub>[`examples/hardware_kit.rs`](../../crates/x0k-release-metadata/examples/hardware_kit.rs) · `#kit` · assembles [kit-keys](#chunk-kit-keys) · [kit-prepare](#chunk-kit-prepare) · [kit-finish](#chunk-kit-finish) · [kit-webauthn](#chunk-kit-webauthn)</sub>

```rust {#kit file="examples/hardware_kit.rs"}
//! The hardware signing kit: prepares a vector, prints a WebAuthn challenge,
//! signs as a WebAuthn signer program, and finishes a signed vector.
//!
//! Run by kit/sign-hardware-vectors.sh; see the hardware-kit chapter.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};
use x0k_release_metadata::{
    canonical_json, key_id, parse_utc, verify, Artifact, Fetched, TrustedState, NAMESPACE,
};

const NOW: &str = "2026-11-05T00:00:00Z";
const LATER: &str = "2030-01-01T00:00:00Z";
const ARTIFACT: &[u8] = b"chariot 1.0\n";
const PATH: &str = "fleet/chariot-1.0.tar";

<<kit-keys>>

<<kit-prepare>>

<<kit-finish>>

<<kit-webauthn>>

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = match words.as_slice() {
        ["prepare", dir, public, custody, flags @ ..] if flags.iter().all(|f| ["--touch", "--batch"].contains(f)) => {
            let shape = Shape { touch: flags.contains(&"--touch"), batch: flags.contains(&"--batch") };
            prepare_vector(Path::new(dir), public, custody, shape)
        }
        ["challenge", staged] => print_challenge(Path::new(staged)),
        ["check-assertion", assertion] => check_assertion(Path::new(assertion)),
        ["finish", dir, claim] => finish_vector(Path::new(dir), claim),
        ["-Y", "sign", "-n", namespace, "-f", assertion] => webauthn_sign(namespace, Path::new(assertion)),
        _ => Err(KitError::Usage),
    };
    if let Err(error) = outcome {
        let _ = writeln!(std::io::stderr(), "hardware_kit: {error}");
        std::process::exit(2);
    }
}

#[derive(Debug, thiserror::Error)]
enum KitError {
    #[error("usage: hardware_kit prepare <vector dir> <key.pub> <custody> [--touch] [--batch] | challenge <staged.json> | check-assertion <assertion.json> | finish <vector dir> <claim> | -Y sign -n <namespace> -f <assertion.json>")]
    Usage,
    #[error("{path}: {source}")]
    File { path: PathBuf, source: std::io::Error },
    #[error("{0}")]
    Refused(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

fn read_kit_file(path: &Path) -> Result<Vec<u8>, KitError> {
    fs::read(path).map_err(|source| KitError::File { path: path.to_owned(), source })
}

fn write_kit_file(path: &Path, bytes: &[u8]) -> Result<(), KitError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| KitError::File { path: parent.to_owned(), source })?;
    }
    fs::write(path, bytes).map_err(|source| KitError::File { path: path.to_owned(), source })
}

fn pretty_json(value: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec_pretty(value).unwrap_or_default();
    out.push(b'\n');
    out
}
```

The software keys are TUF `ed25519` keys from fixed seeds. The hardware
key's object is built from the line `ssh-keygen` or the page printed: the
comment is dropped, the scheme is `sshsig-` and the key type without
`@openssh.com`, and the custody is the one the operator names.

<a name="chunk-kit-keys"></a><sub>[`examples/hardware_kit.rs`](../../crates/x0k-release-metadata/examples/hardware_kit.rs) · `#kit-keys`</sub>

```rust {#kit-keys}
/// A software key of the vector's cast.
struct SoftKey {
    id: String,
    object: Value,
    key: SigningKey,
}

impl SoftKey {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let object = json!({
            "keytype": "ed25519", "scheme": "ed25519",
            "keyval": { "public": hex::encode(key.verifying_key().as_bytes()) },
        });
        Self { id: key_id(&object).unwrap_or_default(), object, key }
    }

    fn sign(&self, body: &Value) -> Value {
        let message = canonical_json(body).unwrap_or_default();
        json!({ "keyid": self.id, "sig": hex::encode(self.key.sign(&message).to_bytes()) })
    }
}

fn signed(body: Value, keys: &[&SoftKey]) -> Value {
    let signatures: Vec<Value> = keys.iter().map(|key| key.sign(&body)).collect();
    json!({ "signed": body, "signatures": signatures })
}

/// The key object for a hardware key's public line.
fn hardware_key(line: &str, custody: &str) -> Result<(String, Value), KitError> {
    let mut words = line.split_whitespace();
    let (Some(keytype), Some(encoded)) = (words.next(), words.next()) else {
        return Err(KitError::Refused(format!("not an SSH public key line: {line}")));
    };
    let scheme = format!("sshsig-{}", keytype.trim_end_matches("@openssh.com"));
    let object = json!({
        "keytype": keytype, "scheme": scheme, "keyval": { "public": format!("{keytype} {encoded}") },
        "x-release-metadata-signatory": "operator", "x-release-metadata-custody": custody,
    });
    Ok((key_id(&object).map_err(|e| KitError::Refused(e.to_string()))?, object))
}

struct Cast {
    root: [SoftKey; 2],
    targets: SoftKey,
    online: SoftKey,
}

fn kit_cast() -> Cast {
    Cast { root: [SoftKey::new(1), SoftKey::new(2)], targets: SoftKey::new(20), online: SoftKey::new(10) }
}
```

`prepare` writes the vector's trusted root, its top-level targets and the
unsigned `fleet` body with the artifact beside it. The kit then stages and
signs that body with the ceremony. A batch vector also delegates `pilot/*`
to the hardware key and writes an unsigned `pilot` body, and the kit signs
both files with one call to `sign`, so the device signs a batch statement
once (decision §3).

<a name="chunk-kit-prepare"></a><sub>[`examples/hardware_kit.rs`](../../crates/x0k-release-metadata/examples/hardware_kit.rs) · `#kit-prepare`</sub>

```rust {#kit-prepare}
/// What a hardware vector proves besides the scheme: the touch rule, and
/// one batch signature over two files.
struct Shape {
    touch: bool,
    batch: bool,
}

fn prepare_vector(dir: &Path, public: &str, custody: &str, shape: Shape) -> Result<(), KitError> {
    let Shape { touch, batch } = shape;
    let line = String::from_utf8_lossy(&read_kit_file(Path::new(public))?).trim().to_owned();
    let (hardware_id, hardware) = hardware_key(&line, custody)?;
    let c = kit_cast();
    let mut keys = Map::new();
    for key in [&c.root[0], &c.root[1], &c.targets, &c.online] {
        keys.insert(key.id.clone(), key.object.clone());
    }
    let rules = if touch { json!({ "operator": { "flags": ["user-present"] } }) } else { json!({}) };
    let root = json!({
        "_type": "root", "spec_version": "1.0.37", "consistent_snapshot": false, "version": 1, "expires": LATER,
        "keys": keys,
        "roles": {
            "root": { "keyids": [c.root[0].id, c.root[1].id], "threshold": 2 },
            "timestamp": { "keyids": [c.online.id], "threshold": 1 },
            "snapshot": { "keyids": [c.online.id], "threshold": 1 },
            "targets": { "keyids": [c.targets.id], "threshold": 1 },
        },
        "x-release-metadata-signatories": rules,
    });
    let hardware_listing: Map<String, Value> = [(hardware_id.clone(), hardware)].into_iter().collect();
    let audience = |name: &str| {
        json!({ "name": name, "keyids": [hardware_id], "threshold": 1, "terminating": true, "paths": [format!("{name}/*")] })
    };
    let roles = if batch { vec![audience("fleet"), audience("pilot")] } else { vec![audience("fleet")] };
    let targets = json!({
        "_type": "targets", "spec_version": "1.0.37", "version": 1, "expires": LATER, "targets": {},
        "delegations": { "keys": hardware_listing, "roles": roles },
    });
    let entry = json!({
        "length": ARTIFACT.len(),
        "hashes": { "sha256": hex::encode(Sha256::digest(ARTIFACT)), "sha512": hex::encode(Sha512::digest(ARTIFACT)) },
    });
    let entries: Map<String, Value> = [(PATH.to_owned(), entry)].into_iter().collect();
    let fleet = json!({
        "_type": "targets", "spec_version": "1.0.37", "version": 1, "expires": LATER, "targets": entries,
    });
    write_kit_file(&dir.join("trusted/root.json"), &pretty_json(&signed(root, &[&c.root[0], &c.root[1]])))?;
    write_kit_file(&dir.join("fetched/targets.json"), &pretty_json(&signed(targets, &[&c.targets])))?;
    write_kit_file(&dir.join("fleet.body.json"), &pretty_json(&fleet))?;
    if batch {
        let pilot = json!({ "_type": "targets", "spec_version": "1.0.37", "version": 1, "expires": LATER, "targets": {} });
        write_kit_file(&dir.join("pilot.body.json"), &pretty_json(&pilot))?;
    }
    write_kit_file(&dir.join("artifact.tar"), ARTIFACT)
}
```

`finish` runs after the ceremony has signed `fetched/fleet.json`, and
`fetched/pilot.json` for a batch vector. It writes the snapshot over every
targets file there and the timestamp over the snapshot, and the case, then
verifies the vector with the crate itself and prints the outcome. It
removes the bodies and the artifact, so the directory holds only what a
vector holds.

<a name="chunk-kit-finish"></a><sub>[`examples/hardware_kit.rs`](../../crates/x0k-release-metadata/examples/hardware_kit.rs) · `#kit-finish`</sub>

```rust {#kit-finish}
fn kit_meta(bytes: &[u8]) -> Value {
    json!({ "version": 1, "length": bytes.len(), "hashes": { "sha256": hex::encode(Sha256::digest(bytes)) } })
}

fn finish_vector(dir: &Path, claim: &str) -> Result<(), KitError> {
    let c = kit_cast();
    let mut files = BTreeMap::new();
    for role in ["targets", "fleet", "pilot"] {
        let path = dir.join(format!("fetched/{role}.json"));
        if role != "pilot" || path.exists() {
            files.insert(role.to_owned(), read_kit_file(&path)?);
        }
    }
    let meta: Map<String, Value> = files.iter().map(|(role, bytes)| (format!("{role}.json"), kit_meta(bytes))).collect();
    let snapshot = json!({
        "_type": "snapshot", "spec_version": "1.0.37", "version": 1, "expires": LATER, "meta": meta,
    });
    let snapshot = pretty_json(&signed(snapshot, &[&c.online]));
    let timestamp = json!({
        "_type": "timestamp", "spec_version": "1.0.37", "version": 1, "expires": LATER,
        "meta": { "snapshot.json": kit_meta(&snapshot) },
    });
    let timestamp = pretty_json(&signed(timestamp, &[&c.online]));
    write_kit_file(&dir.join("fetched/snapshot.json"), &snapshot)?;
    write_kit_file(&dir.join("fetched/timestamp.json"), &timestamp)?;
    let sha256 = hex::encode(Sha256::digest(ARTIFACT));
    let case = json!({
        "decision": "§3",
        "claim": claim,
        "now": NOW,
        "target": { "path": PATH, "length": ARTIFACT.len(), "hashes": { "sha256": sha256 } },
        "expect": { "verified": { "role": "fleet" } },
    });
    write_kit_file(&dir.join("case.json"), &pretty_json(&case))?;
    let fetched = Fetched { roots: Vec::new(), timestamp, snapshot, targets: files };
    let trusted = TrustedState::from_root(read_kit_file(&dir.join("trusted/root.json"))?);
    let artifact = Artifact { length: ARTIFACT.len() as u64, hashes: [("sha256".to_owned(), sha256)].into() };
    let now = parse_utc(NOW).map_err(|e| KitError::Refused(e.to_string()))?;
    let verified = verify(&trusted, &fetched, PATH, &artifact, now)
        .map_err(|refusal| KitError::Refused(format!("the vector does not verify: {refusal}")))?;
    for leftover in ["fleet.body.json", "pilot.body.json", "artifact.tar"] {
        let _ = fs::remove_file(dir.join(leftover));
    }
    let _ = writeln!(std::io::stdout(), "{}: verified by role {}", dir.display(), verified.target.role);
    Ok(())
}
```

## The passkey

OpenSSH cannot make a WebAuthn signature, so a passkey signs through a
browser. The page `kit/passkey.html` is served from `localhost` and uses
no network beyond it. It registers a new passkey for the relying party
`localhost` and prints its public key as an `sk-ecdsa` key line whose
application is `localhost`. Later it asks the passkey to sign a
challenge, and prints the authenticator data, the client data, the
signature and the key line as one JSON object.

The challenge is the SSHSIG blob of the staged body, the bytes an SSHSIG
signer signs, which `challenge` prints in unpadded base64url. A batch
signs a statement that `sign` builds, so its challenge comes from `sign`
itself: called before the assertion is saved, the kit's signer prints the
blob of the message it was given as the challenge, and makes no
signature; the operator signs it on the page and runs `sign` again. The
kit is the signer program for `sign`: called as
`hardware_kit -Y sign -n release-metadata -f <assertion.json>`, it reads
the message on its standard input, checks that the assertion's challenge
is that message's blob, that the authenticator signed for the key's
application, and wraps the parts in the
`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature of an SSHSIG
envelope, armored as `ssh-keygen` writes it. The verifier then checks it
as it checks every other signature.

<a name="chunk-kit-webauthn"></a><sub>[`examples/hardware_kit.rs`](../../crates/x0k-release-metadata/examples/hardware_kit.rs) · `#kit-webauthn`</sub>

```rust {#kit-webauthn}
fn ssh_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.extend(u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend(*field);
    }
    out
}

/// The blob an SSHSIG signer signs for `message` under `namespace`.
fn sshsig_blob(namespace: &str, message: &[u8]) -> Vec<u8> {
    let mut blob = b"SSHSIG".to_vec();
    blob.extend(ssh_fields(&[namespace.as_bytes(), b"", b"sha512", &Sha512::digest(message)]));
    blob
}

fn print_challenge(staged: &Path) -> Result<(), KitError> {
    #[derive(Deserialize)]
    struct Staged {
        signed: Value,
    }
    let staged: Staged = serde_json::from_slice(&read_kit_file(staged)?)?;
    let message = canonical_json(&staged.signed).map_err(|e| KitError::Refused(e.to_string()))?;
    let challenge = Base64UrlUnpadded::encode_string(&sshsig_blob(NAMESPACE, &message));
    let _ = writeln!(std::io::stdout(), "{challenge}");
    Ok(())
}

/// What the passkey page prints after the passkey signs.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Assertion {
    public_key: String,
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
}

#[derive(Deserialize)]
struct ClientData {
    challenge: String,
    origin: String,
}

/// Refuses an assertion file that is missing, empty or not the page's JSON.
fn check_assertion(path: &Path) -> Result<(), KitError> {
    serde_json::from_slice::<Assertion>(&read_kit_file(path)?)?;
    Ok(())
}

fn kit_refusal(why: &str) -> KitError {
    KitError::Refused(why.to_owned())
}

fn webauthn_sign(namespace: &str, assertion_path: &Path) -> Result<(), KitError> {
    let mut message = Vec::new();
    std::io::stdin()
        .read_to_end(&mut message)
        .map_err(|source| KitError::File { path: PathBuf::from("<stdin>"), source })?;
    let blob = sshsig_blob(namespace, &message);
    if !fs::metadata(assertion_path).is_ok_and(|meta| meta.len() > 0) {
        let challenge = Base64UrlUnpadded::encode_string(&blob);
        let _ = writeln!(std::io::stderr(), "challenge: {challenge}");
        let wanted = assertion_path.display();
        return Err(KitError::Refused(format!("no assertion yet: sign the challenge on the passkey page, save it as {wanted}, and sign again")));
    }
    let assertion: Assertion = serde_json::from_slice(&read_kit_file(assertion_path)?)?;
    let decode = |text: &str| Base64UrlUnpadded::decode_vec(text.trim_end_matches('=')).map_err(|_| kit_refusal("bad base64url"));
    let authenticator_data = decode(&assertion.authenticator_data)?;
    let client_data = decode(&assertion.client_data_json)?;
    let der = decode(&assertion.signature)?;
    let parsed: ClientData = serde_json::from_slice(&client_data)?;
    if decode(&parsed.challenge)? != blob {
        return Err(kit_refusal("the passkey signed another challenge than this staged file's"));
    }
    let (keytype, encoded) = assertion.public_key.split_once(' ').ok_or_else(|| kit_refusal("bad key line"))?;
    let public = Base64::decode_vec(encoded.split_whitespace().next().unwrap_or("")).map_err(|_| kit_refusal("bad key line"))?;
    let application = key_application(&public).ok_or_else(|| kit_refusal("not an sk-ecdsa key line"))?;
    if keytype != "sk-ecdsa-sha2-nistp256@openssh.com" {
        return Err(kit_refusal("not an sk-ecdsa key line"));
    }
    if authenticator_data.len() < 37 || authenticator_data[..32] != Sha256::digest(&application)[..] {
        return Err(kit_refusal("the authenticator signed for another relying party than the key's application"));
    }
    let flags = authenticator_data[32];
    let counter = &authenticator_data[33..37];
    let extensions = &authenticator_data[37..];
    let (r, s) = der_scalars(&der).ok_or_else(|| kit_refusal("bad DER signature"))?;
    let signature = ssh_fields(&[&mpint(r), &mpint(s)]);
    let mut sig_blob = ssh_fields(&[b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com", &signature]);
    sig_blob.push(flags);
    sig_blob.extend(counter);
    sig_blob.extend(ssh_fields(&[parsed.origin.as_bytes(), &client_data, extensions]));
    let mut envelope = b"SSHSIG".to_vec();
    envelope.extend(1u32.to_be_bytes());
    envelope.extend(ssh_fields(&[&public, namespace.as_bytes(), b"", b"sha512", &sig_blob]));
    let encoded = Base64::encode_string(&envelope);
    let mut armored = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for line in encoded.as_bytes().chunks(70) {
        armored.push_str(&String::from_utf8_lossy(line));
        armored.push('\n');
    }
    armored.push_str("-----END SSH SIGNATURE-----\n");
    let _ = std::io::stdout().write_all(armored.as_bytes());
    Ok(())
}

/// The application of an `sk-ecdsa` key's wire encoding.
fn key_application(public: &[u8]) -> Option<Vec<u8>> {
    let mut rest = public;
    let mut field = || {
        let len = usize::try_from(u32::from_be_bytes(rest.get(..4)?.try_into().ok()?)).ok()?;
        let value = rest.get(4..4 + len)?;
        rest = &rest[4 + len..];
        Some(value)
    };
    let (_keytype, _curve, _point, application) = (field()?, field()?, field()?, field()?);
    Some(application.to_vec())
}

/// The two integers of a DER ECDSA signature, as WebAuthn returns it.
fn der_scalars(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let body = der.strip_prefix(&[0x30])?;
    let (&len, body) = body.split_first()?;
    let body = body.get(..usize::from(len))?;
    let (r, rest) = der_integer(body)?;
    let (s, _) = der_integer(rest)?;
    Some((r, s))
}

/// One DER INTEGER, and the bytes after it.
fn der_integer(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let bytes = bytes.strip_prefix(&[0x02])?;
    let (&len, bytes) = bytes.split_first()?;
    Some((bytes.get(..usize::from(len))?, bytes.get(usize::from(len)..)?))
}

fn mpint(integer: &[u8]) -> Vec<u8> {
    let start = integer.iter().position(|byte| *byte != 0).unwrap_or(integer.len());
    let mut out = integer[start..].to_vec();
    if out.first().is_some_and(|byte| byte & 0x80 != 0) {
        out.insert(0, 0);
    }
    out
}
```

The page holds its own code and needs nothing from the network. Chrome
treats `http://localhost` as a secure origin, so WebAuthn runs there.
When Chrome asks where to keep the passkey, the operator picks their
phone and scans the code; a FIDO2 security key also works, and still
signs through WebAuthn.

<a name="chunk-passkey-page"></a><sub>[`kit/passkey.html`](../../crates/x0k-release-metadata/kit/passkey.html) · `#passkey-page`</sub>

```html {#passkey-page file="kit/passkey.html"}
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Passkey vector</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; margin: 2em auto; max-width: 52em; padding: 0 1em; }
  textarea { width: 100%; height: 6em; font: 12px/1.4 ui-monospace, monospace; }
  button { font-size: 15px; margin: 0.5em 0; }
  #log { color: #a00; white-space: pre-wrap; }
</style>
</head>
<body>
<h1>Passkey vector for x0k-release-metadata</h1>
<p>1. Register a new passkey for <code>localhost</code>. When Chrome asks where to save it, choose your phone and scan the code.</p>
<button id="register">Register a new passkey</button>
<p>Public key line. Save it as <code>keys/passkey.pub</code>:</p>
<textarea id="public" readonly></textarea>
<p>2. Paste the challenge the kit printed, then sign it with the same passkey.</p>
<textarea id="challenge"></textarea>
<button id="sign">Sign the challenge</button>
<p>Assertion. Save it as <code>keys/passkey-assertion.json</code>:</p>
<textarea id="assertion" readonly></textarea>
<p id="log"></p>
<script>
const RP_ID = "localhost";
const enc = new TextEncoder();
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (text) => Uint8Array.from(atob(text.trim().replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const sshString = (bytes) => {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const log = (text) => { document.getElementById("log").textContent = text; };

document.getElementById("register").onclick = async () => {
  try {
    const credential = await navigator.credentials.create({ publicKey: {
      rp: { id: RP_ID, name: "x0k release-metadata vectors" },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "release-metadata-vectors", displayName: "release-metadata vectors" },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      attestation: "none",
    } });
    if (credential.response.getPublicKeyAlgorithm() !== -7) throw new Error("the passkey is not ES256");
    const spki = new Uint8Array(credential.response.getPublicKey());
    const point = spki.slice(spki.length - 65);
    const wire = concat(sshString(enc.encode("sk-ecdsa-sha2-nistp256@openssh.com")), sshString(enc.encode("nistp256")), sshString(point), sshString(enc.encode(RP_ID)));
    const line = "sk-ecdsa-sha2-nistp256@openssh.com " + btoa(String.fromCharCode(...wire));
    localStorage.setItem("credential", b64u(credential.rawId));
    localStorage.setItem("publicKey", line);
    document.getElementById("public").value = line;
    log("");
  } catch (error) { log(String(error)); }
};

document.getElementById("sign").onclick = async () => {
  try {
    const credential = localStorage.getItem("credential");
    if (!credential) throw new Error("register a passkey first");
    const assertion = await navigator.credentials.get({ publicKey: {
      challenge: unb64u(document.getElementById("challenge").value),
      rpId: RP_ID,
      allowCredentials: [{ type: "public-key", id: unb64u(credential) }],
      userVerification: "preferred",
    } });
    document.getElementById("assertion").value = JSON.stringify({
      publicKey: localStorage.getItem("publicKey"),
      authenticatorData: b64u(assertion.response.authenticatorData),
      clientDataJSON: b64u(assertion.response.clientDataJSON),
      signature: b64u(assertion.response.signature),
    }, null, 2);
    log("");
  } catch (error) { log(String(error)); }
};
</script>
</body>
</html>
```

## The script

`kit/sign-hardware-vectors.sh` runs the whole kit. It takes the output
directory, which must not exist yet, and the schemes to sign, and it
writes one vector directory per scheme into it, plus the fresh keys under
`keys/`. Each `batch-` scheme signs a batch vector, `hw-batch-<scheme>`:
the device signs `fleet.json` and `pilot.json` with one call to `sign`.
`batch-enclave` asks for the public line of a Secretive key made for
vectors, and refuses `chariot-root`. Each step says what the operator does: touch the token, approve
in Secretive, or act in the browser. Where the operator saves a file, the
kit waits until it is there: a key line must be non-empty, and the
passkey's assertion must parse as the page's JSON (`check-assertion`)
before the kit signs with it. A file saved in the wrong place gets a new
prompt, not an exit.

<a name="chunk-kit-script"></a><sub>[`kit/sign-hardware-vectors.sh`](../../crates/x0k-release-metadata/kit/sign-hardware-vectors.sh) · `#kit-script`</sub>

```bash {#kit-script file="kit/sign-hardware-vectors.sh"}
#!/usr/bin/env bash
# Signs one x0k-release-metadata conformance vector per hardware scheme with
# the real signer (decision release-metadata §3). See the hardware-kit chapter.
#
#   kit/sign-hardware-vectors.sh <new output dir> [fido2-ed25519] [fido2-ecdsa] [enclave] [passkey]
#       [batch-fido2-ed25519] [batch-fido2-ecdsa] [batch-enclave] [batch-passkey]

#
# Environment: X0K_RELEASE_METADATA_BIN (the directory holding the built
# x0k-release-metadata program and examples/hardware_kit), SSH_KEYGEN
# (an ssh-keygen with FIDO2 support), SECRETIVE_SOCK (Secretive's agent socket).
set -euo pipefail

OUT=${1:?usage: sign-hardware-vectors.sh <new output dir> [fido2-ed25519] [fido2-ecdsa] [enclave] [passkey] [batch-...]}
shift
if [ $# -gt 0 ]; then SCHEMES=("$@"); else SCHEMES=(fido2-ed25519 fido2-ecdsa enclave passkey); fi
CHALLENGE_FIRST=
BIN=${X0K_RELEASE_METADATA_BIN:?set X0K_RELEASE_METADATA_BIN to the target directory holding x0k-release-metadata}
SSH_KEYGEN=${SSH_KEYGEN:-/opt/homebrew/bin/ssh-keygen}
SECRETIVE_SOCK=${SECRETIVE_SOCK:-$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh}
CLI="$BIN/x0k-release-metadata"
KIT="$BIN/examples/hardware_kit"
KIT_DIR=$(cd "$(dirname "$0")" && pwd)

[ ! -e "$OUT" ] || { echo "refusing: $OUT exists; name a new directory" >&2; exit 2; }
for tool in "$CLI" "$KIT" "$SSH_KEYGEN"; do [ -x "$tool" ] || { echo "missing: $tool" >&2; exit 2; }; done
mkdir -p "$OUT/keys"
OUT=$(cd "$OUT" && pwd)

say() { printf '\n== %s\n' "$*"; }

# wait_for_file <path>: re-prompts until the operator has saved a non-empty file there.
wait_for_file() {
  until [ -s "$1" ]; do
    read -r -p "$1 is missing or empty; save it there and press Enter... " _
  done
}

# sign_vector <name> <key.pub> <custody> <touch:yes|no> <signer> <key arg> <claim>
sign_vector() {
  local name=$1 public=$2 custody=$3 touch=$4 signer=$5 key=$6 claim=$7
  local dir="$OUT/$name"
  if [ "$touch" = yes ]; then
    "$KIT" prepare "$dir" "$public" "$custody" --touch
  else
    "$KIT" prepare "$dir" "$public" "$custody"
  fi
  "$CLI" stage "$dir/fleet.body.json" "$dir/fetched/fleet.json"
  if [ -n "${CHALLENGE_FIRST:-}" ]; then
    say "Paste this challenge into the passkey page, press 'Sign the challenge', and save the assertion as $key"
    "$KIT" challenge "$dir/fetched/fleet.json"
    read -r -p "Press Enter once $key is saved... " _
    until "$KIT" check-assertion "$key"; do
      read -r -p "$key is missing, empty or not the page's JSON; save the assertion there and press Enter... " _
    done
  fi
  "$CLI" sign "$dir/fetched/fleet.json" --trusted "$dir/trusted/root.json" \
    --delegator "$dir/fetched/targets.json" --role fleet --key "$key" --signer "$signer" \
    --rebuilt "fleet/chariot-1.0.tar=$dir/artifact.tar"
  "$CLI" status "$dir/fetched/fleet.json" --trusted "$dir/trusted/root.json" \
    --delegator "$dir/fetched/targets.json" --role fleet
  "$KIT" finish "$dir" "$claim"
}

# batch_vector <name> <key.pub> <custody> <touch:yes|no> <signer> <key arg> <claim>: the device
# signs fleet.json and pilot.json with one batch signature, through one call to sign.
batch_vector() {
  local name=$1 public=$2 custody=$3 touch=$4 signer=$5 key=$6 claim=$7
  local dir="$OUT/$name"
  if [ "$touch" = yes ]; then
    "$KIT" prepare "$dir" "$public" "$custody" --touch --batch
  else
    "$KIT" prepare "$dir" "$public" "$custody" --batch
  fi
  "$CLI" stage "$dir/fleet.body.json" "$dir/fetched/fleet.json"
  "$CLI" stage "$dir/pilot.body.json" "$dir/fetched/pilot.json"
  sign_both() {
    "$CLI" sign "$dir/fetched/fleet.json" "$dir/fetched/pilot.json" --trusted "$dir/trusted/root.json" \
      --delegator "$dir/fetched/targets.json" --key "$key" --signer "$signer" \
      --rebuilt "fleet/chariot-1.0.tar=$dir/artifact.tar"
  }
  if [ -n "${CHALLENGE_FIRST:-}" ]; then
    say "Paste the challenge printed below into the passkey page, press 'Sign the challenge', and save the assertion as $key"
    sign_both || true
    read -r -p "Press Enter once $key is saved... " _
    until "$KIT" check-assertion "$key"; do
      read -r -p "$key is missing, empty or not the page's JSON; save the assertion there and press Enter... " _
    done
  fi
  sign_both
  "$KIT" finish "$dir" "$claim"
}

for scheme in "${SCHEMES[@]}"; do
  case "$scheme" in
    fido2-ed25519)
      say "FIDO2 ed25519: touch the security key to make a new key, then touch it again to sign"
      "$SSH_KEYGEN" -t ed25519-sk -N "" -C "" -f "$OUT/keys/fido2-ed25519"
      sign_vector hw-fido2-ed25519 "$OUT/keys/fido2-ed25519.pub" fido2 yes "$SSH_KEYGEN" "$OUT/keys/fido2-ed25519" \
        "A FIDO2 token's sk-ssh-ed25519 signature, made by the token with a touch, counts for a signatory whose rule demands the touch."
      ;;
    fido2-ecdsa)
      say "FIDO2 ecdsa: touch the security key to make a new key, then touch it again to sign"
      "$SSH_KEYGEN" -t ecdsa-sk -N "" -C "" -f "$OUT/keys/fido2-ecdsa"
      sign_vector hw-fido2-ecdsa "$OUT/keys/fido2-ecdsa.pub" fido2 yes "$SSH_KEYGEN" "$OUT/keys/fido2-ecdsa" \
        "A FIDO2 token's sk-ecdsa-sha2-nistp256 signature, made by the token with a touch, counts for a signatory whose rule demands the touch."
      ;;
    enclave)
      say "Secure Enclave: in Secretive, create a new key named release-metadata-vectors, then save its public key as $OUT/keys/enclave.pub"
      read -r -p "Press Enter once $OUT/keys/enclave.pub is saved... " _
      wait_for_file "$OUT/keys/enclave.pub"
      line=$(awk '{print $1" "$2}' "$OUT/keys/enclave.pub")
      case "$line" in ecdsa-sha2-nistp256\ *) ;; *) echo "refusing: enclave.pub is not an ecdsa-sha2-nistp256 key" >&2; exit 2;; esac
      if SSH_AUTH_SOCK="$SECRETIVE_SOCK" ssh-add -L 2>/dev/null | grep -i 'chariot-root' | awk '{print $1" "$2}' | grep -qxF "$line"; then
        echo "refusing: enclave.pub is the chariot-root key" >&2; exit 2
      fi
      SSH_AUTH_SOCK="$SECRETIVE_SOCK" ssh-add -L | awk '{print $1" "$2}' | grep -qxF "$line" \
        || { echo "refusing: Secretive's agent does not hold enclave.pub" >&2; exit 2; }
      say "Approve the signature in Secretive's prompt"
      export SSH_AUTH_SOCK="$SECRETIVE_SOCK"
      sign_vector hw-enclave-ecdsa "$OUT/keys/enclave.pub" secure-enclave no "$SSH_KEYGEN" "$OUT/keys/enclave.pub" \
        "A Secure Enclave key's ecdsa-sha2-nistp256 signature, made through Secretive, counts."
      unset SSH_AUTH_SOCK
      ;;
    passkey)
      say "Passkey: serving the page at http://localhost:8000/passkey.html; open it in Chrome and register a new passkey on your phone"
      python3 -m http.server 8000 --bind 127.0.0.1 --directory "$KIT_DIR" >/dev/null 2>&1 &
      server=$!
      trap 'kill $server 2>/dev/null || true' EXIT
      read -r -p "Press Enter once the key line is saved as $OUT/keys/passkey.pub... " _
      wait_for_file "$OUT/keys/passkey.pub"
      CHALLENGE_FIRST=1
      sign_vector hw-passkey-webauthn "$OUT/keys/passkey.pub" passkey no "$KIT" "$OUT/keys/passkey-assertion.json" \
        "A passkey's WebAuthn signature over the SSHSIG blob, made on a phone through Chrome, counts."
      CHALLENGE_FIRST=
      kill "$server" 2>/dev/null || true
      ;;
    batch-fido2-ed25519)
      say "FIDO2 ed25519 batch: touch the security key to make a new key, then touch it once to sign two files"
      "$SSH_KEYGEN" -t ed25519-sk -N "" -C "" -f "$OUT/keys/batch-fido2-ed25519"
      batch_vector hw-batch-fido2-ed25519 "$OUT/keys/batch-fido2-ed25519.pub" fido2 yes "$SSH_KEYGEN" "$OUT/keys/batch-fido2-ed25519" \
        "A FIDO2 token's sk-ssh-ed25519 batch signature, made with one touch, counts on both files its statement lists for a signatory whose rule demands the touch."
      ;;
    batch-fido2-ecdsa)
      say "FIDO2 ecdsa batch: touch the security key to make a new key, then touch it once to sign two files"
      "$SSH_KEYGEN" -t ecdsa-sk -N "" -C "" -f "$OUT/keys/batch-fido2-ecdsa"
      batch_vector hw-batch-fido2-ecdsa "$OUT/keys/batch-fido2-ecdsa.pub" fido2 yes "$SSH_KEYGEN" "$OUT/keys/batch-fido2-ecdsa" \
        "A FIDO2 token's sk-ecdsa-sha2-nistp256 batch signature, made with one touch, counts on both files its statement lists for a signatory whose rule demands the touch."
      ;;
    batch-enclave)
      if [ ! -s "$OUT/keys/enclave.pub" ]; then
        say "Secure Enclave batch: save the public key of a Secretive key made for vectors, never chariot-root, as $OUT/keys/enclave.pub"
        read -r -p "Press Enter once $OUT/keys/enclave.pub is saved... " _
        wait_for_file "$OUT/keys/enclave.pub"
      fi
      line=$(awk '{print $1" "$2}' "$OUT/keys/enclave.pub")
      case "$line" in ecdsa-sha2-nistp256\ *) ;; *) echo "refusing: enclave.pub is not an ecdsa-sha2-nistp256 key" >&2; exit 2;; esac
      if SSH_AUTH_SOCK="$SECRETIVE_SOCK" ssh-add -L 2>/dev/null | grep -i 'chariot-root' | awk '{print $1" "$2}' | grep -qxF "$line"; then
        echo "refusing: enclave.pub is the chariot-root key" >&2; exit 2
      fi
      SSH_AUTH_SOCK="$SECRETIVE_SOCK" ssh-add -L | awk '{print $1" "$2}' | grep -qxF "$line" \
        || { echo "refusing: Secretive's agent does not hold enclave.pub" >&2; exit 2; }
      say "Secure Enclave batch: approve the one signature in Secretive's prompt, if it asks"
      export SSH_AUTH_SOCK="$SECRETIVE_SOCK"
      batch_vector hw-batch-enclave-ecdsa "$OUT/keys/enclave.pub" secure-enclave no "$SSH_KEYGEN" "$OUT/keys/enclave.pub" \
        "A Secure Enclave key's ecdsa-sha2-nistp256 batch signature, made through Secretive with one approval, counts on both files its statement lists."
      unset SSH_AUTH_SOCK
      ;;
    batch-passkey)
      say "Passkey batch: serving the page at http://localhost:8000/passkey.html; open it in Chrome and register a new passkey on your phone"
      python3 -m http.server 8000 --bind 127.0.0.1 --directory "$KIT_DIR" >/dev/null 2>&1 &
      server=$!
      trap 'kill $server 2>/dev/null || true' EXIT
      read -r -p "Press Enter once the key line is saved as $OUT/keys/batch-passkey.pub... " _
      wait_for_file "$OUT/keys/batch-passkey.pub"
      CHALLENGE_FIRST=1
      batch_vector hw-batch-passkey-webauthn "$OUT/keys/batch-passkey.pub" passkey no "$KIT" "$OUT/keys/batch-passkey-assertion.json" \
        "A passkey's WebAuthn batch signature over the statement's SSHSIG blob, made on a phone through Chrome, counts on both files its statement lists."
      CHALLENGE_FIRST=
      kill "$server" 2>/dev/null || true
      ;;
    *) echo "unknown scheme $scheme" >&2; exit 2 ;;
  esac
done

say "Done. Copy $OUT back; its hw-* directories are conformance vectors."
```
