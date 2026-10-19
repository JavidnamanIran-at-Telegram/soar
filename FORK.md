# Why this fork exists

Upstream [getlantern/soar](https://github.com/getlantern/soar) is a DNS tunnel for a public,
anonymous, last-resort transport. One server key is shared by everyone who holds it, and
`ServerConfig.Dial` is handed `(ctx, network, addr)` — nothing about *who* is asking. For
Lantern's own use that is not a gap, it is the design.

It is a gap for anyone running Soar for a known set of accounts, which is what a per-member
tunnel service is. Such an operator has to invent identity outside the protocol, and the two ways
that exist both leak:

1. **One server instance per account**, each with its own zone and key. No protocol change, but
   the per-account zone is still in the query name, and the cost scales badly — one process
   serving ~1,800 accounts measures 9 MB RSS and under 2% of one core; the same accounts as
   separate instances is three to four orders of magnitude more memory, plus a keypair, a socket
   and a delegation each.
2. **A per-account label above the zone**. One process, cheap, no client change — and a cleartext
   bearer token in every query name.

This fork does two things about that. It makes option 2 as safe as it can be made, since it is
what keeps existing clients working, and it adds a third option that is actually private, for a
client that can be changed. Both are optional and both are off by default: a server and client
that set neither are byte-for-byte upstream v1.

The design is also written up as a proposal to upstream. If it is taken, this fork's reason to
exist goes away, which would be the best outcome.

## What it adds

**EXT frame (`0x10`).** A frame with a sub-type and an explicit length, so an unknown sub-type is
skipped instead of killing the session. Upstream's §6 makes an unknown frame *type* fatal and the
single-byte space below `0x10` is full (`0x00`–`0x07` allocated, `0x08`–`0x0F` STREAM), so
without a reserved type nothing can ever be added to v1. This is the hook, and the identity frame
is its first user.

**Account label in the query name** (`IdentifyByLabel`). The label directly above the zone names
the account; the client is configured with a longer zone and nothing else changes. The fork:

- folds the label to lower case, because a resolver may randomize the case of a name on the way to
  the server (0x20 encoding) — without this, such a resolver knocks an account offline;
- restricts it to `a-z`, `0-9`, `-`, `_`, at most 63 bytes. A DNS label may hold any octet, and
  this one ends up in account lookups, log lines and backend credentials;
- **pins it to the hello**, so a later query cannot re-attribute a live session, and ignores a
  mismatch rather than failing the session — the name is not authenticated, so ending the session
  on it would hand any resolver on the path a way to kill an account;
- authorizes it at the hello, *before* the key generation, ECDH and signature that answering a
  hello costs, so an unknown account buys nothing;
- caps concurrent sessions per account (`MaxSessionsPerAccount`), so one account — or one copied
  label — cannot fill `MaxSessions`.

What it cannot do, and the fork says so in every place it is documented: the label is in the query
name in cleartext. It is a bearer credential and a stable selector. Encrypting it changes nothing,
because the client sends one fixed zone verbatim on every query, so the label is constant and a
constant ciphertext is as copyable as a constant hash.

**IDENT frame** (`VerifyClient`, `Config.Identity`). A client proves its account with
`HMAC-SHA256(key, "soar v1 client auth" || key_id || T)[:16]` over the handshake transcript `T`,
in an EXT frame in its first upstream packet — inside the session's encryption. A resolver sees
ciphertext; there is no per-account string in any name and no per-account zone to delegate; and
`T` holds both ephemeral public keys and the session id, so a captured proof authenticates nothing
else.

The proof is a 16-byte MAC and not a public key and signature because of a constraint that only
shows up in the implementing: the whole frame has to fit one packet, frames are never split, and
at the 101-character name length some networks impose a packet carries about 40 bytes of frames.
An Ed25519 key and signature are 96 bytes on their own and could never ride the first packet.
There is a test for this (`TestIdentFrameFitsTheSafeQueryName`) so it cannot quietly regress.

**Query parsing with no heap allocations.** Not about identity, but the label check lives in the
same function, which runs on every query the server receives:

```
                      before            after
BenchmarkParseQuery   191 ns  624 B  6 allocs →  145 ns  192 B  2 allocs
BenchmarkParseQueryLabel                          147 ns  192 B  3 allocs
```

A name's labels and their concatenated base32 now go in stack buffers, which also meant bounding
the name at its real limit: 255 wire bytes (RFC 1035 §2.3.4). Upstream took the sender's framing
for it, so a 4 KB message could present two thousand labels; that is now refused.

## What it does not change

- The wire format, when identity is off. Upstream's test vectors still pass unmodified; the new
  ones are additions.
- The handshake, the key schedule, packet protection, packet numbers, the carrier, streams, flow
  control, loss detection, holding, discovery — untouched.
- Default behaviour anywhere. `IdentifyByLabel`, `VerifyLabel`, `VerifyClient`,
  `RequireIdentity`, `MaxSessionsPerAccount` and `Config.Identity` all default to off or nil.

## The diff

| file | what |
|---|---|
| `identity.go` | new: the whole feature — frame encoding, the proof, label validation, the context, per-account accounting |
| `identity_test.go` | new: the tests below |
| `frames.go` | the EXT type and its parsing |
| `dnswire.go` | `zone.userLabel`, the label split, allocation-free parsing, the 255-byte name bound |
| `server.go` | the `ServerConfig` fields, authorization at the hello, the identity context, `RequireIdentity` |
| `session.go` | the `onExt` hook, the IDENT send queue and its retransmission |
| `client.go` | `Config.Identity`, `ClientIdentity`, the proof queued at the end of the handshake |
| `cmd/soar-server/` | `-accounts` (hot-reloaded), `-identify-by-label`, `-require-identity`, `-max-sessions-per-account` |
| `SPEC.md` | §6 EXT, §11 client identity |
| `parse_bench_test.go` | new: the parsing benchmark above |

Everything identity-related that could live in one file does, so the diff against upstream stays
small and a rebase stays cheap.

## Tests

`go test ./...` runs upstream's suite unchanged plus:

| test | what it pins down |
|---|---|
| `TestLabelIdentityReachesDial` | the account reaches `Dial`, and a label identity does not claim to be sealed |
| `TestUnknownLabelIsRefusedBeforeTheHandshake` | an unknown account gets a REFUSED and never reaches `Dial` |
| `TestMalformedLabelIsRefused` | spaces, newlines, terminal escapes, punctuation — all refused |
| `TestLabelCaseIsFolded` | a case-randomizing resolver does not knock an account offline |
| `TestLabelIsPinnedToTheHandshake` | an on-path resolver rewriting the label on live queries cannot get one account charged to another |
| `TestMaxSessionsPerAccount` | the cap binds, and binds per account |
| `TestSealedIdentityReachesDial` | end to end, sealed, with the account at `Dial` |
| `TestSealedIdentityIsNotInTheQueryName` | no credential and no constant selector in any query name |
| `TestSealedProofIsBoundToItsSession` | the proof does not carry to another session, sid or key id |
| `TestSealedIdentityRejectedEndsTheSession` | a proof that does not verify gets no traffic and no `Dial` |
| `TestRequireIdentityRefusesAnUnidentifiedClient` | and neither does a client that never identifies |
| `TestIdentityOffBehavesLikeUpstream` | with neither mode set, the whole name is payload again |
| `TestUnknownExtensionSubTypeIsSkipped` | the point of EXT: the frames after an unknown one still arrive |
| `TestOverlongNameIsRefused` | a name past 255 wire bytes is malformed, however it is framed |

The suite is clean under `-race`.

## Keeping up with upstream

```sh
git remote add upstream https://github.com/getlantern/soar.git
git fetch upstream
git rebase upstream/main
```

Forked at upstream `a8af533` (`v0.2.3`, 2026-10-17). If a wire-format change lands upstream,
regenerate the vectors after rebasing:

```sh
go test -run TestVectors -update-vectors
```
