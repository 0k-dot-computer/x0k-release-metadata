# Release Metadata

```turtle folio:document
architecture:release-metadata a x0k:Architecture ;
    x0k:status "accepted" ;
    x0k:summary "A user's machine installs a release only when the publisher's root says that enough maintainers signed it for that machine's audience. The root names each maintainer, their keys, and how many maintainers must sign each record. Each record has a version and an expiry date, so an old or withheld release does not verify. Each signature is an SSHSIG envelope, so FIDO2 tokens, Secure Enclave keys, phone passkeys and software keys make one format, and one signature can cover several records, so a release takes one touch of a security key. A threshold counts maintainers, not keys. The root changes only when enough maintainers of the old version and of the new version sign the new version, one at a time. The record layout is TUF's, and the verifier is a pure function, published alone." ;
    x0k:concerns "trust", "delivery", "publication", "signing", "keys" ;
    x0k:supports design:distribution-and-updates ;
    x0k:dependsOn architecture:service-authorization ;
    x0k:motivatedBy architecture:distribution-channels,
        architecture:publication-is-the-shipping-unit,
        intent:f15a74b5-00f4-8f20-ea80-52a6e8542cd4 ;
    x0k:mentions architecture:identity,
        architecture:approver,
        architecture:trust-mesh-and-membership,
        architecture:operation-surface,
        architecture:timeline-public-surface,
        wiki:release-signing-prior-art .
```

## Brief

Most projects sign a release with one key. That key is a maintainer's GPG
key, or a key on the build server so that each build can sign itself. A
person who holds that key, or who breaks into that server, can ship a
release that every user installs. This decision gives the maintainers of a
project one record instead. The record says who may sign a release, how
many of them must sign, and which of their devices count.

A maintainer signs with a key that they already have. This can be a FIDO2
token, the Mac's Secure Enclave through an app such as Secretive, a passkey
on a phone, or a key file. All of these make the same kind of signature.
One signature can cover every file of a release, so a maintainer touches
their security key once per release. A user's machine checks each release
against the record. It refuses the
release if too few maintainers signed it, or if they signed it for a
different audience. It also refuses it if the rule of a maintainer was not
met, for example "two of my keys" or "a touch on the token".

The record can change, because people lose keys and people leave. A change
needs enough maintainers from the old record and from the new record. Each
maintainer signs the new record on their own machine, one after another,
so the maintainers do not have to meet. The build server holds only a key
that says the record is current. A thief with that key can delay an update
but cannot forge one. The record format and its verifier are one published
package that needs no x0k. chariot, a developer tool with its own
maintainers, uses it as an ordinary dependency, and x0k's own channels use
it the same way.

## Context

`distribution-channels` §3 decides that a release is a signed manifest.
Trust attaches to the key of the author, never to the URL that the bytes
came from. Each promotion is signed for one audience, and the author key
can be in hardware. Section 3 leaves two questions open: how a publisher
of several people says who may sign, and whether a public release needs
more than one touch. `identity` §2 decides a sequence of keys under a cold
root for one person. A group of maintainers is not a person, and no
decision covers it.

chariot's maintainers asked for the same thing from the other side. They
want a master record that names the signing keys, needs more than one
person to change, and lets them replace keys. Signatures come from FIDO2
tokens, the Secure Enclave, a phone or a software key, and a later method
must be possible. They also asked where to keep the signatures: in git as
SOPS-encrypted files, or only on the CI server.

The practice this decision leaves is one signing key per publisher.
x0k-approver already signs an approval with `ssh-keygen -Y sign` (scheme
`sshsig`), a FIDO2 assertion (`fido2-assertion`) or an SSH certificate.
No x0k code counts signatures toward a threshold yet.
<!-- open for the operator: WRITING.md asks for a number from outside x0k on what single-key release signing has cost; none was gathered for this draft. -->

### What a verifier must stop

A user's machine downloads a release from servers that it does not trust:
a mirror, a CDN, a cache, a network that an attacker controls. A signature
on the release file alone does not make this safe. The table gives each
attack, what the attacker does, and the part of this decision that stops
it. The attack names follow the TUF specification 1.0.37, § "Goals to
protect against specific attacks". The wrong-audience row is not TUF's;
`distribution-channels` §3 adds it.

| Attack | What the attacker does | What stops it |
|---|---|---|
| Arbitrary installation | Serves a file that the publisher never released | Each artifact's length and hashes are in a signed record (§1) |
| Rollback | Serves an older release, correctly signed, that has a known defect | Each record has a version, and a machine never goes back to a lower one (§1) |
| Indefinite freeze | Serves the same old, valid records again and again, so the machine never sees a fix | Each record has an expiry date, and one record expires soon (§1, §6) |
| Mix-and-match | Serves records from two releases that never existed together | One record lists the version of every other record (§1) |
| Wrong audience | Serves a release for testers to a machine that installs only public releases | Each audience has its own role and keys (§2) |
| Key compromise | Steals one key, or the build server | Each record needs a threshold of signatures, and the keys that sign releases are not on the server (§4, §6) |

A further problem is not an attack: a maintainer loses a key or leaves the
project. The record of who may sign must then change, and a machine that
trusts the old record must be able to trust the new one (§5).

### Prior art

The outside designs surveyed (`principle:adopt-before-invent`). Each is
read against this decision, with its sources, in
`x0k:wiki/release-signing-prior-art`.

- **TUF**, The Update Framework
  ([specification](https://theupdateframework.github.io/specification/latest/),
  version 1.0.37). It defines the attacks above and a set of signed files
  that stop them. python-tuf, go-tuf and tough implement it. This decision
  adopts TUF's roles, file formats, client workflow and root rotation rule.
  Together they stop every attack in the table.
- **tuf-on-ci** runs a TUF repository on a CI platform, and Sigstore and
  GitHub use it for their roots. A change is a signing event: a pull
  request that each keyholder signs with their own hardware key, one
  after another. Each key object names its owner in
  `x-tuf-on-ci-keyowner`, and one online key signs the snapshot and the
  timestamp. This decision adopts the signing event (§5) and the one
  online key (§6).
- **SSHSIG**, OpenSSH's signature envelope (`PROTOCOL.sshsig` in OpenSSH).
  It signs a hash of a message under a namespace, with any key that
  `ssh-agent` can hold. FIDO2 `sk-` keys and Secretive's Secure Enclave
  keys both make it, and git verifies it through `allowed_signers`. This
  decision adopts it as the signature format.
- **Sigstore** signs without long-lived keys. An OIDC identity provider
  issues a short-lived certificate, and a public transparency log records
  each signature. Signing needs that provider online, and trust ends at
  the provider. chariot's maintainers sign offline with their own
  hardware, so this decision does not adopt it. A later scheme can carry
  it.
- **minisign and signify** use one key, with no threshold and no rotation.
  They do not meet the need.
- **in-toto** records the steps of a supply chain and who did each step.
  It answers who built what, which this decision does not decide. It can
  be added next to TUF later.

This decision adds two things to TUF and tuf-on-ci. The first is the
SSHSIG signature schemes (§3). The second is a threshold that counts
maintainers instead of keys, which is how the root states the quorum of
`service-authorization` §10 (§4). tuf-on-ci already records who owns each
key, but its thresholds still count keys.

## Decision

### 1. Four signed records, each with a version and an expiry

**Decides:** what the trust record of a publisher is and how it is laid
out.
**Invariants:** every metadata file is signed, has a version and expires;
a reader never accepts a version lower than one it already trusts.
**On failure:** the verifier refuses the update and names the role and the
rule that failed; the reader keeps its last trusted state.
**Checked by:** the release-metadata conformance vectors (intent
700bda19), TUF's client-workflow cases among them.

The trust record of a publisher is four signed files. Each file has one
job:

- **`root.json`** names the keys that may sign each of the four files, and
  how many of those keys must sign. A machine gets its first root with the
  software, so its trust starts at this file.
- **`targets.json`** lists each artifact by its length and its hashes. If
  one byte of a download differs, the download does not verify.
- **`snapshot.json`** lists the version of every targets file. A machine
  reads targets files only at those versions, so it cannot combine files
  from two releases.
- **`timestamp.json`** names the current snapshot and expires soon. When
  a machine has only an expired timestamp, it knows that it does not have
  the current release.

TUF calls each of these files a role, and this decision uses that word.
Each file holds a `signed` body and the `signatures` over that body. The
body has a version number and an expiry date. A reader keeps the highest
version of each role that it has trusted. The verifier refuses a lower
version, and it refuses an expired file. The file names, the fields and
the serialization are TUF's (§ "Roles and PKI" and § "Document formats"),
in TUF's canonical JSON. Maintainers review a change to these files as a
text diff before they sign it, so what they read is what they sign. Where
x0k carries a file across one of its own boundaries, which use canonical
CBOR, the record holds the signed JSON bytes as one opaque field and never
encodes them again.

<a name="folio-instance-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d656e636f64696e67-1"></a><sub data-instance-iri="x0k:open-question/release-metadata-encoding" data-concept-iri="https://0k.computer/ontology#OpenQuestion" data-source-document="corpora/x0k/decisions/architecture/delivery/release-metadata.md"><strong>OpenQuestion</strong> · Unresolved instance · <code>x0k:open-question/release-metadata-encoding</code> · <a href="#folio-source-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d656e636f64696e67-1">source declaration</a> · the graph block at line 180 is not Turtle: The prefix open-question: has not been declared at corpora/x0k/decisions/architecture/delivery/release-metadata.md:179</sub><a name="folio-source-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d656e636f64696e67-1"></a>

```turtle folio:graph
@prefix open-question: <https://0k.computer/ontology#open-question/> .
open-question:release-metadata-encoding a x0k:OpenQuestion ;
    x0k:text "Is the metadata canonical JSON, as TUF specifies, or canonical CBOR, as every x0k boundary is?" ;
    x0k:description "Canonical JSON lets python-tuf, go-tuf and tough read a repository whose keys use TUF's own schemes, and is the recommended default. operation-surface section 1 and timeline-public-surface spell every x0k boundary in canonical CBOR. CBOR would keep x0k's one spelling and give up the TUF tools. Resolved 2026-11-05: canonical JSON (operator: \"Canonical JSON\"), after the operator asked about canonical CBOR with a JSON converter. A JSON view of CBOR cannot be checked against signatures over the CBOR bytes, and stock TUF clients verify none of the SSHSIG schemes in either encoding, so the deciding reason is that maintainers review the signed bytes themselves as a git diff. Section 1 states it." ;
    x0k:status "resolved" .
```

### 2. An audience is a delegated targets role

**Decides:** how a signature names the audience it is valid for.
**Invariants:** a target verifies only under the role its path is
delegated to; a target's path is its audience's name, a `/` and a file
name with no further `/`; one artifact promoted to two audiences is two
targets, each with its own signatures.
**On failure:** the verifier refuses a target whose path no delegation
covers, as unknown.
**Checked by:** the conformance vectors: the verifier refuses an artifact
signed for `fleet` when a reader looks it up for `pilot`, and refuses a
path two levels under an audience.

One artifact can go to more than one audience. x0k's audiences are
`fleet/`, the owner's own machines, `pilot/`, the machines of pilot users,
and `public/`, everyone. chariot names its own. A signature for one
audience must not make the artifact install for another.

A targets role can delegate. It names a second role, the paths that the
second role may list, and the keys and threshold of the second role. TUF
calls the second role a delegated targets role (§ "File formats:
targets.json and delegated target roles"). The top-level targets role
delegates one role for each audience. A reader is enrolled for one
audience, and it looks up only the paths of that audience. This delegation
is the audience of `distribution-channels` §3.

A delegation names its paths as TUF path patterns. In a TUF pattern, `*`
matches any characters except `/`. So the targets of an audience are
flat: each path is the audience's name and one file name, for example
`fleet/x0k-0.1.0-aarch64-darwin.tar`. The delegation of that audience is
the one pattern `fleet/*`, and a standard TUF client reads it the same way
as this verifier. The version and the platform go in the file name. The
verifier does not refuse a delegation that lists other patterns as well,
because it refuses every path deeper than one file name under an audience,
whatever the patterns say.

The same bytes signed for `fleet` are a different target from those bytes
signed for `public`. The format does not let one stand for the other. An
audience that reaches more machines can have a larger threshold. For
example, `public` can require two maintainers while `fleet` requires one.
Each root sets every threshold, and no audience has a fixed one.
chariot's root needs two signatories to change, so admitting or removing a
maintainer takes two of them, and one signatory signs a release.

<a name="folio-instance-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d7075626c69632d72756e67-2"></a><sub data-instance-iri="x0k:open-question/release-metadata-public-rung" data-concept-iri="https://0k.computer/ontology#OpenQuestion" data-source-document="corpora/x0k/decisions/architecture/delivery/release-metadata.md"><strong>OpenQuestion</strong> · Unresolved instance · <code>x0k:open-question/release-metadata-public-rung</code> · <a href="#folio-source-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d7075626c69632d72756e67-2">source declaration</a> · the graph block at line 180 is not Turtle: The prefix open-question: has not been declared at corpora/x0k/decisions/architecture/delivery/release-metadata.md:179</sub><a name="folio-source-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d7075626c69632d72756e67-2"></a>

```turtle folio:graph
@prefix open-question: <https://0k.computer/ontology#open-question/> .
open-question:release-metadata-public-rung a x0k:OpenQuestion ;
    x0k:text "Does distribution-channels section 3's public rung become the public role's threshold of two signatories?" ;
    x0k:description "Section 3 leaves open whether a public release needs a second factor, a second person or a delay. This decision makes a second person expressible as a threshold. The recommended default folds that rule into section 3 when both are accepted; a delay would be a further rule this format does not yet express. Resolved 2026-11-05: each root sets every threshold, and distribution-channels section 3 fixes none for public (operator: \"Each root sets it. For chariot we admit or revoke a signatory (maintainer) only with 2 or more signatories present ... Only one must sign to release Chariot.\"). Section 2 states it, with chariot's root as the example." ;
    x0k:status "resolved" .
```

<a name="folio-instance-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d61686561642d6f662d74696d65-3"></a><sub data-instance-iri="x0k:open-question/release-metadata-ahead-of-time" data-concept-iri="https://0k.computer/ontology#OpenQuestion" data-source-document="corpora/x0k/decisions/architecture/delivery/release-metadata.md"><strong>OpenQuestion</strong> · Unresolved instance · <code>x0k:open-question/release-metadata-ahead-of-time</code> · <a href="#folio-source-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d61686561642d6f662d74696d65-3">source declaration</a> · the graph block at line 180 is not Turtle: The prefix open-question: has not been declared at corpora/x0k/decisions/architecture/delivery/release-metadata.md:179</sub><a name="folio-source-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d61686561642d6f662d74696d65-3"></a>

```turtle folio:graph
@prefix open-question: <https://0k.computer/ontology#open-question/> .
open-question:release-metadata-ahead-of-time a x0k:OpenQuestion ;
    x0k:text "May the signatories approve a release before it is built, by signing a delegation of one version's path to a key that a session holds?" ;
    x0k:description "distribution-channels section 8 signs the manifest after the build, because the touch must cover the exact artifacts. So an agent session that prepares the next version of a crate cannot get a signature until the artifact exists, and the owner must be present at that moment. Candidate: the signatories sign a delegated targets role that names the public half of a key the session made, exactly one version's path (for example public/x0k-folio/0.7.0/*), and an end no later than the approver's 24-hour grant ceiling. The session signs the artifact when it is ready. A threshold of two inside the delegation (the session's key and the CI key) makes the verifier check that the gates passed. The delegation is declared, bounded by its one path and its end, narrower than the signatories' own role, and revocable by a new targets version, which are debug-channel section 9's four conditions for a bounded grant. The cost: the signatories do not see the final change, and anything resident on the session's machine can use the key until the end. Candidate default: allowed for fleet and pilot; for public, only when the full quorum signs the delegation. This pressures distribution-channels section 8 and approver section 2, whose payload would be a delegation and not a release. Resolved 2026-11-05 as the candidate (operator: \"Yes, as the candidate says\"); section 8 decides it." ;
    x0k:status "resolved" .
```

### 3. Every signature is an SSHSIG envelope

**Decides:** the signature format, which keys can sign, and how one
signature covers several files.
**Invariants:** a signature covers the canonical bytes of the `signed`
body under the namespace `release-metadata`, or the canonical bytes of a
batch statement under the namespace `release-metadata-batch`; a batch
signature counts on a file only when its statement lists that file's
type, role, version and body hash; the package verifies every scheme
itself and runs no program to do it; a WebAuthn signature's client data
carries the signed bytes' SSHSIG blob as its challenge, and the verifier
checks its origin for form only.
**On failure:** the verifier does not count a signature under another
namespace, of an unknown scheme, by a key the role does not list, with
client data that carries another challenge, or whose batch statement does
not list this file or lists another version or body hash, and names
which.
**Checked by:** the conformance vectors, one per scheme, each signature
made by the real signer; a passkey signature whose client data carries
another challenge does not count; a passkey signature made with the
origin `http://localhost:8000` counts; one batch signature per scheme
counts on each file it lists; a batch signature under the single
namespace, a single signature under the batch namespace, and a batch
statement that omits the file or lists another hash, version, role or
type do not count; a token's batch signature without the touch flag does
not count where the rule demands it.

A signature is a value that only the holder of a private key can make over
some bytes. Anyone with the matching public key can check it. TUF's own
`ed25519` scheme signs the bytes of the `signed` body directly. A FIDO2
token cannot do this. It signs a structure of its own, which holds a hash
of the bytes, flags and a counter. One of the flags shows that a person
touched the token. SSHSIG is an envelope that carries this structure, and
every signer that the maintainers named already makes it.

A key object keeps TUF's `keytype`, `scheme` and `keyval` fields. The
schemes are TUF's own `ed25519` for software keys, and SSHSIG over the key
types that an SSH agent holds:

| Scheme | Typical signer |
|---|---|
| `sshsig-ssh-ed25519` | A software key, or an x0k device key |
| `sshsig-ecdsa-sha2-nistp256` | A Secure Enclave key through Secretive |
| `sshsig-sk-ssh-ed25519` | A FIDO2 token |
| `sshsig-sk-ecdsa-sha2-nistp256` | A FIDO2 token, or a phone's passkey |

An SSHSIG key object holds the public key as `ssh-keygen` prints it: the
key type, a space and the base64 key, with no comment, for example
`sk-ssh-ed25519@openssh.com AAAA…`. Its `keytype` is that key type. This
one form holds every SSH key type, and a FIDO2 key keeps the application
string that its signatures cover. A signature's `sig` field is the binary
SSHSIG envelope in lowercase hex, as TUF writes every signature. The
verifier also accepts uppercase hex, as TUF clients do.

A phone's passkey signs through WebAuthn. WebAuthn puts the challenge
inside a block of client data, and the authenticator signs that client
data. OpenSSH defines this form as the
`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature type for an
`sk-ecdsa` key. The package carries it inside the same SSHSIG envelope.

The verifier checks the client data as OpenSSH's own verifier does. The
client data must begin with the type `webauthn.get`, the SSHSIG blob as
its challenge and the origin, in that order. The verifier checks the
origin for form only: it must hold no quote character, and the verifier
does not compare it with a site. The relying party is already bound,
because the authenticator signs a hash of the relying party's id, and the
verifier takes that id from the key's application. So a passkey made for
`localhost` signs releases as a passkey made on a publisher's site does.

The namespace is fixed. So a release signature does not verify as a git
commit signature or a file signature that the same key made. A new signing
method adds a scheme name and its verifier, and it changes no metadata
field.

A FIDO2 token makes one signature per touch, and a release is several
files. So one signature can cover several files: a **batch signature**.
The signer signs a batch statement, a canonical JSON object whose `_type`
is `release-metadata-batch` and whose `files` list names each covered
file by its `_type`, its role, its `version` and the SHA-256 of the
canonical bytes of its `signed` body:

```json
{ "_type": "release-metadata-batch",
  "files": [ { "_type": "targets", "role": "stable", "version": 4, "hashes": { "sha256": "…" } },
             { "_type": "snapshot", "role": "snapshot", "version": 9, "hashes": { "sha256": "…" } } ] }
```

The role is a top-level role's name or a delegated role's name. Each
covered file carries an ordinary `signatures` entry: the `keyid`, the one
batch signature as `sig`, and the statement in
`x-release-metadata-batch`. A TUF client reads past that field. An SSHSIG
batch signature is made under its own namespace, `release-metadata-batch`,
so it never verifies as a signature over one file, and a signature over
one file never verifies as a batch signature. TUF's `ed25519` scheme has
no namespace; there the statement's `_type` keeps the two apart, because
no role's body has that type.

The verifier counts a batch signature on a file when the signature
verifies over the statement and the statement lists this file's type,
role, version and body hash. The signature then counts as that key's
signature on the file. The signatory's rule applies to it as to any other
signature: it is one of their keys, and an `sk` signature carries the
flags the rule demands. Every scheme signs a statement as it signs a body,
and a passkey's client data carries the statement's SSHSIG blob as its
challenge. A signature over one file keeps its form, so a file signed
before batch signatures existed verifies unchanged.

<a name="folio-instance-78306b3a746563686e652f7665726966792d612d72656c656173652d616761696e73742d6974732d726f6f74-4"></a><sub data-instance-iri="x0k:techne/verify-a-release-against-its-root" data-concept-iri="https://0k.computer/ontology#Techne" data-source-document="corpora/x0k/decisions/architecture/delivery/release-metadata.md"><strong>Techne</strong> · Unresolved instance · <code>x0k:techne/verify-a-release-against-its-root</code> · <a href="#folio-source-78306b3a746563686e652f7665726966792d612d72656c656173652d616761696e73742d6974732d726f6f74-4">source declaration</a> · the graph block at line 180 is not Turtle: The prefix open-question: has not been declared at corpora/x0k/decisions/architecture/delivery/release-metadata.md:179</sub><a name="folio-source-78306b3a746563686e652f7665726966792d612d72656c656173652d616761696e73742d6974732d726f6f74-4"></a>

```turtle folio:graph
@prefix techne: <https://0k.computer/ontology#techne/> .
techne:verify-a-release-against-its-root a x0k:Techne ;
    x0k:status "proposed" ;
    x0k:realizes affordance:install_publication,
        affordance:update_bundle .
```

### 4. The root states a quorum: signatories, rules and custody

**Decides:** how the metadata states the quorum of `service-authorization`
§10 for each role.
**Invariants:** only distinct signatories meet a role's threshold; a
signatory counts only when their own rule is met; one public key is listed
under one key id; the verifier checks a presence rule against the
signature's flags, and a flag counts only where the signatory's rule
demands it; a custody claim changes only with the root.
**On failure:** the verifier names each signatory that signed but did not
count, and why, naming a flag the rule demands and the signature lacks. It
refuses a root that lists one public key under two key ids, and a root
whose presence rule names a key whose signatures cannot prove presence,
before any release is read.
**Checked by:** the conformance vectors: one signatory signing with two
keys does not meet a threshold of two; a root that lists one public key
under two signatories is refused; a token signature without the touch flag
does not count for a signatory whose rule demands one; a real token's
signature that counts under a rule demanding `user-present` does not
count under a rule that also demands `user-verified`; the verifier
refuses a root whose presence rule names a non-`sk` key.

TUF counts distinct keys toward a threshold. A maintainer can hold
several keys: a token, a laptop key and a phone passkey. If the root lists
all three for one role, that maintainer alone meets a threshold of two. So
a threshold of keys does not prove that two people agreed.

`service-authorization` §10 decides what a quorum is. A quorum counts
signatories, the people who may sign. Each signatory sets a rule for their
own keys. Only some signatures prove that a person was present, and the
place where a key is kept is a claim, not a proof. This section decides
how the root states it:

- Each key object names its signatory, one maintainer, in
  `x-release-metadata-signatory`, and its custody in
  `x-release-metadata-custody`: `fido2`, `secure-enclave`, `passkey` or
  `software`. A key that names no signatory is its own signatory, under
  its key id, so a root with none of these fields counts as TUF counts.
- A role lists keys and a threshold of signatories.
- The root holds the rule of each signatory in
  `x-release-metadata-signatories`. The rule says how many of their listed
  keys must sign, in `keys_required`, one by default. It says which `sk`
  flags a counted signature must carry, in `flags`: `user-present`, flag
  `0x01`, shows that a person touched the token, and `user-verified`, flag
  `0x04`, shows that the token checked their PIN or biometric.
- A FIDO2 key can also carry its enrollment attestation
  (`ssh-keygen -O write-attestation`), and the signers of the root can
  check it.

A flag counts only where the signatory's rule demands it. A signatory
whose rule names no flags counts an `sk` signature that carries none, so a
signature made without a touch counts for them. `ssh-keygen -Y verify`
differs: it demands the touch flag unless the allowed-signers line says
`no-touch-required`. This package puts the demand in the signatory's rule,
because each signatory sets the rule for their own keys, and the root
states it.

The `x-release-metadata-` prefix keeps these fields apart from any field
that a later TUF version adds. tuf-on-ci names its own fields the same way,
for example `x-tuf-on-ci-keyowner`.

A key id is the hash of the whole key object, so the signatory field is
part of it. The same public key could then be listed twice, under two
signatories with two key ids, and one signature would count for both. So
the verifier refuses a root that lists one public key under two key ids.

When each signatory holds one key per role and has no rule, the count of
signatories and the count of keys are equal. A standard TUF client then
reads the repository the same way as this verifier, but only when every
key uses one of TUF's own schemes. Standard clients do not verify the
SSHSIG schemes of §3, so a root that FIDO2 tokens, Secure Enclave keys or
passkeys sign verifies only in this package.

### 5. The root changes by a new version, signed one signatory at a time

**Decides:** how keys rotate, how a maintainer leaves, and what the
ceremony is.
**Invariants:** a reader trusts root version N+1 only when it carries the
threshold of version N's root role and of its own; a reader walks every
version from its last trusted root.
**On failure:** the verifier refuses a root missing either threshold, and
the reader stays on the root it trusts.
**Checked by:** the conformance vectors for rotation, a removed key, and a
root signed only by its new keys.

A reader that trusts root version N must decide whether version N+1 is
real. It accepts N+1 only when two thresholds are met. Enough signatories
of version N must sign it, which shows that the people the reader already
trusts agree. Enough signatories of version N+1 must also sign it, which
shows that the new keys work. A reader that missed several versions checks
each version in turn, from its last trusted root to the newest. This is
TUF's rule (§ "Key management and migration" and § "Update the root
role"). `service-authorization` §10 requires the same rule of any record
that names signatories.

A new signing key, a new maintainer and a removed maintainer are each a
new root version. The ceremony is tuf-on-ci's signing event, without the
dependence on a pull request:

1. One maintainer stages the new root.
2. Each signer adds a signature with their own key, on their own machine.
3. The package shows which signatories are still missing, until both
   thresholds are met.

A signer adds one signature per signing, however many staged files it
covers (§3). When the new root changes the top-level targets file, a
signer whose key both files' thresholds list signs the root and that
targets file with one batch signature, so the ceremony takes one touch
from each signer. The targets file is checked against the new root,
because that is the root a reader holds when it reads that file. No
signer sees the key of another signer. The keys of the root role sign
only roots. A first root, version 1, has no earlier version, so only its
own threshold applies, and the same ceremony signs it one signatory after
another; each reader pins it at install (§1).

<a name="folio-instance-78306b3a746563686e652f7369676e2d612d726f6f742d6f6e652d7369676e61746f72792d61742d612d74696d65-5"></a><sub data-instance-iri="x0k:techne/sign-a-root-one-signatory-at-a-time" data-concept-iri="https://0k.computer/ontology#Techne" data-source-document="corpora/x0k/decisions/architecture/delivery/release-metadata.md"><strong>Techne</strong> · Unresolved instance · <code>x0k:techne/sign-a-root-one-signatory-at-a-time</code> · <a href="#folio-source-78306b3a746563686e652f7369676e2d612d726f6f742d6f6e652d7369676e61746f72792d61742d612d74696d65-5">source declaration</a> · the graph block at line 180 is not Turtle: The prefix open-question: has not been declared at corpora/x0k/decisions/architecture/delivery/release-metadata.md:179</sub><a name="folio-source-78306b3a746563686e652f7369676e2d612d726f6f742d6f6e652d7369676e61746f72792d61742d612d74696d65-5"></a>

```turtle folio:graph
@prefix techne: <https://0k.computer/ontology#techne/> .
techne:sign-a-root-one-signatory-at-a-time a x0k:Techne ;
    x0k:status "proposed" ;
    x0k:realizes affordance:publish_publication .
```

### 6. Only freshness keys are online, and metadata is public

**Decides:** where keys and signatures live.
**Invariants:** no key that signs root or targets metadata is on a build
server; every metadata file is public; the signing command signs a
targets entry only when its hashes match the signer's own rebuild, or when
the signer states that the build is not reproducible; a snapshot or
timestamp signed in the same batch as a file it lists lists that file by
version only.
**On failure:** a thief with the online key can withhold the newest
release until the timestamp expires, and cannot make a release verify.
**Checked by:** the conformance vectors: the verifier refuses targets
metadata signed only by the online key; a release whose targets file,
snapshot and timestamp one key signs in one batch verifies; under a
version-only listing, another file of that version verifies only when
its role's signatories signed it. Ceremony tests: a rebuild that differs
from the targets entry, or no rebuild, is refused by the signing command;
a release is signed with one call to the signer.

The timestamp expires soon, so a key must sign a new one often. A person
cannot sign it each day, so a key on the build server signs it. That key
is one software `ed25519` key, and it signs both the snapshot and the
timestamp roles. The build server keeps it in its secret store, and it is
the only release secret on the build server. The package builds the
snapshot from the targets files it lists and the timestamp from the
snapshot, and signs each through the signer program of §7, so the build
server's scheduled refresh is one command; signed that way, the online
key's object uses the `sshsig-ssh-ed25519` scheme. A thief with this key can
sign a new timestamp for an old snapshot. That makes a freeze last longer,
but it cannot make a reader accept an artifact that a maintainer did not
sign.

A root may also list a maintainer's key for the snapshot and timestamp
roles. That maintainer then signs a release in one step: the targets file
of the release's role, the snapshot that lists it, and the timestamp that
lists the snapshot, with one batch signature (§3), so the release takes
one touch. The online key still refreshes the timestamp between releases.
A listing of a whole file's hashes covers that file's signatures, so a
snapshot cannot list the hashes of a file signed in the same batch. The
package therefore lists such a file by version only, which TUF allows,
and lists every other file by version, length and hashes. The verifier
checks a version-only listing by version: it accepts a file of that
version that meets its role's threshold. Two different files of one
version exist only if that role's signatories signed both. A file made by
anyone else carries no signature that counts, because a batch signature
taken from the real file names the real body's hash.

A build makes the artifacts and the unsigned targets entries. Then a key
of a maintainer signs them. A signature is not a secret. The metadata is
kept in a git repository or branch that the publisher controls, and each
release's metadata is copied next to its artifacts. No part of it needs an
encrypted secrets file.

A build server that an attacker controls can make a bad artifact and a
correct targets entry for it. So where the build is reproducible, the
signer rebuilds the artifact from the tagged source on their own machine
and gives the signing command the rebuilt files. The command runs no
build itself. It refuses to sign when a rebuilt file's hashes differ from
the targets entry, and it names both. A threshold of two signatories is
then also two independent builds. Where the build is not reproducible,
the signer says so with an explicit flag on the signing command; without
a rebuild or that flag, the command refuses. The signatures then show who
approved a release, not how it was built, and the publisher's threat
model says so. in-toto layouts, which record each build
step and who performed it, can be a later scheme.

<a name="folio-instance-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d6275696c642d636f6d70726f6d697365-6"></a><sub data-instance-iri="x0k:open-question/release-metadata-build-compromise" data-concept-iri="https://0k.computer/ontology#OpenQuestion" data-source-document="corpora/x0k/decisions/architecture/delivery/release-metadata.md"><strong>OpenQuestion</strong> · Unresolved instance · <code>x0k:open-question/release-metadata-build-compromise</code> · <a href="#folio-source-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d6275696c642d636f6d70726f6d697365-6">source declaration</a> · the graph block at line 180 is not Turtle: The prefix open-question: has not been declared at corpora/x0k/decisions/architecture/delivery/release-metadata.md:179</sub><a name="folio-source-78306b3a6f70656e2d7175657374696f6e2f72656c656173652d6d657461646174612d6275696c642d636f6d70726f6d697365-6"></a>

```turtle folio:graph
@prefix open-question: <https://0k.computer/ontology#open-question/> .
open-question:release-metadata-build-compromise a x0k:OpenQuestion ;
    x0k:text "What must a maintainer's signing command check about how an artifact was built before it signs the artifact's targets entry?" ;
    x0k:description "Section 6 puts the build on a server and the signing keys on the maintainers' machines, so a compromised build server makes a bad artifact that the maintainers sign. Signing then shows who approved a release, not what was built. Partial answers: (1) where the build is reproducible, the signing command rebuilds from the tagged source on the signer's machine and refuses to sign when its hashes differ from the targets entry, so a threshold of two signatories is also two independent builds; (2) an in-toto layout names the build steps, who may perform each and a threshold per step, and the verifier refuses an artifact without the matching link metadata (wiki:release-signing-prior-art, in-toto); (3) nothing, with the gap stated as a consequence. The candidate default is (1) where a reproducible build exists and (3) elsewhere, with (2) as a later scheme. This pressures section 6's claim that only freshness keys are online and design:distribution-and-updates's promise that the resolver verifies every release. Resolved 2026-11-05 as the candidate (operator: \"Rebuild where reproducible\"); section 6 decides it." ;
    x0k:status "resolved" .
```

### 7. The verifier is a pure function, published alone

**Decides:** the package's boundary.
**Invariants:** the verifier opens no connection and reads no clock; the
package depends on no x0k crate; the ceremony commands sign only through
the signer program they are given.
**On failure:** a reader that cannot fetch metadata keeps its trusted
state and reports the fetch as its own failure.
**Checked by:** the conformance vectors, run against the published crate
from a clean clone (intent 700bda19), and a ceremony test that signs a
root through a stub signer program.

The verifier takes five inputs: the reader's trusted state, the fetched
metadata, a target path, the hashes of the target and the current time. It
returns the verified target and the new trusted state. If the check fails,
it returns a refusal that names the role, the rule and the signatories.
The embedder fetches the files: chariot's updater, or x0k's channel
resolver. The package also has commands that stage a root, add a
signature and show what is missing, because the ceremony of §5 is part of
its surface.

The commands do not hold or choose a key. They call a signer program with
the arguments and output of `ssh-keygen -Y sign`: the key, the namespace,
and the message, and an SSHSIG signature back. git signs commits through
the same interface (`gpg.ssh.program`), and this decision adopts it. The
default program is `ssh-keygen`, which reaches a FIDO2 token, a key file
or an SSH agent such as Secretive. A user names another program in one
setting. The package knows nothing about the program it calls.

In x0k, the signer program is a thin client of the node's approver
(`approver` §2). The client sends the whole message, so the approver's
window shows what the root or targets file changes, not a hash. A
quorum's shares go to each signatory's approver. A user of the package
outside x0k keeps `ssh-keygen` and needs nothing else from x0k.

In x0k, the author keyring entry of a publication
(`distribution-channels` §3) is the pinned root of that publication. Its
audiences are the delegated roles of §2. An x0k device key, a did:key over
Ed25519, can be the key of a signatory under `ed25519` or
`sshsig-ssh-ed25519`. x0k-approver's signature schemes converge on the
schemes of this package. So one package verifies `sshsig` and passkey
signatures for both releases and approvals.

### 8. A release can be approved before it is built

**Decides:** how signatories approve one release before its artifact
exists.
**Invariants:** the delegation names one version's files, the public half
of a key that the session made, and an end no later than the approver's
24-hour grant ceiling, which is the expiry of the targets version that
delegates it; it is narrower than the role that delegates it; a
delegation for an audience the root marks public carries the signature of
every signatory that the role lists.
**On failure:** the verifier refuses a target outside the delegated path,
a target under a delegation whose metadata has expired, and a public
delegation that lacks a signatory, and names the rule. The stage command
refuses an audience's targets version that delegates and expires more
than 24 hours after it is staged.
**Checked by:** the conformance vectors: a delegated key's target for the
named version verifies; a target for another version, one under an expired
delegation and a public delegation with one signatory missing are refused.
A ceremony test: staging a delegating version that expires in 25 hours is
refused.

An agent session can prepare the next version of a crate while its
signatories are away. If they must sign after the build, the release waits
for them. So the signatories can approve the release in advance:

1. The session makes a key and asks for a delegation through the approver.
2. The signatories sign a new version of their targets role. It delegates
   one version's files, for example the pattern
   `dev/chariot-0.15.0-dev.3-*`, to the session's key, and it expires
   within 24 hours (`approver` §5).
3. When the artifact is ready, the session signs its targets entry with
   that key.

The delegation can require two signatures: the session's key and the CI
key. Then the verifier itself checks that CI passed.

This is the bounded grant of `debug-channel` §9, applied to a release. It
is declared, it is bounded by one path and one end, it is narrower than
the role that delegates it, and a new targets version revokes it. The
signatories do not see the final change, and any program on the session's
machine can use the key until the end. So the root marks which audiences
are public, such as x0k's `public/` and chariot's `main/`, and a delegation
for one of them needs every signatory that its role lists. The root lists
them by role name in `x-release-metadata-public-audiences`.

The metadata records no start time, so the verifier cannot check the
24-hour ceiling; the stage command checks it when the delegating version
is staged. The verifier also cannot see that a pattern names only one
version's files, or that the session made the key. The signers check both
before they sign, and the status command shows each delegation's pattern
and key id so that they can.

## Rationale

**TUF instead of a format of our own.** Freshness, rollback, mixed
snapshots and root rotation are the difficult parts of an update check.
TUF specifies each one, and several implementations exist, so a new format
would meet each problem again. The additions use fields that TUF lets an
implementation extend. A repository that uses none of them is plain TUF.

**SSHSIG instead of TUF's own signature schemes.** A FIDO2 token cannot
make a raw signature over arbitrary bytes (§3). Every signer that the
maintainers named already makes SSHSIG with tools they have. SSHSIG also
lets a verifier see a touch after the signature is made.

**A batch statement instead of one signature per file.** A token makes one
signature per touch, so a release of three files signed one file at a
time is three touches. A statement that names each file's type, role,
version and body hash lets one signature count on each file, and a reader
of one file still checks a signature that names exactly that file. A
signature over the snapshot alone would not do this: the targets role's
threshold must be met by signatures on the targets file itself.

## Consequences

- A publisher with one maintainer and one key writes a root with
  thresholds of one, and the other features cost it nothing.
- If more root keys are lost than the threshold allows, nobody can change
  the root. Then every user must pin a new root by hand, so the publisher
  sets the root threshold against that risk.
- A maintainer signs each release by hand for every audience whose role
  has no online key. Automation can build, stage and send reminders, but
  it cannot sign. One touch signs the whole release when the root lists
  the maintainer's key for the snapshot and the timestamp too.
- A publisher whose build is not reproducible gets no rebuild check, and
  its threat model states that gap.
- Desktops sign through OpenSSH or an SSH agent. Phones need a small
  passkey signer that builds the SSHSIG envelope from a WebAuthn
  assertion.

## Related Decisions

- [`distribution-and-updates`](../../design/offering/distribution-and-updates.md):
  the design this supports; its resolver "verifies every release against
  the key you chose to trust", and §1 to §5 say what that key is.
- [`distribution-channels`](distribution-channels.md) §3: the signed
  manifest, the author keyring, the audience per promotion and the
  hardware-rooted key, which this decision gives a format. §2 answers its
  audience; `open-question:release-metadata-public-rung` asks whether its
  public rung folds in here.
- [`identity`](../substrate/identity.md): one person's sequence of keys
  under a cold root. A publisher's root here belongs to a group, and an
  x0k identity can be one of its signatories.
- [`service-authorization`](../substrate/service-authorization.md) §10:
  the quorum, signatories, their rules and custody, which §4 states in
  the root.
- [`approver`](../substrate/approver.md): §3 proposes an answer to
  `open-question:approver-passkey-at-the-door` (a passkey signature as
  OpenSSH's WebAuthn form inside SSHSIG) and does not close it.
- [`publication-is-the-shipping-unit`](publication-is-the-shipping-unit.md):
  the package ships as `publication:x0k-release-metadata`.
