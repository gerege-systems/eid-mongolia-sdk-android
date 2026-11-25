[Монгол](README.md) · English · [中文](README.zh-CN.md)

# eID Mongolia — PAdES SDK (Android)

`mn.eidmongolia.eid.pades` — a Kotlin library for eID Mongolia **client-side PAdES** (PDF signing). The PDF never goes to the eID
server: the app prepares the PDF locally (`prepare`), has only the 32-byte DTBS signed by the citizen's phone or USB token,
and embeds the signature into the PDF (`complete`: RFC 3161 timestamp + OCSP/CRL + DSS → PAdES B-LT).

- Android minSdk 24, JDK 17
- Native library, no BouncyCastle — `java.security` + a small DER writer; the only dependency is kotlinx-coroutines
- Profile `pades-client/1` — **byte-identical** output to the Go reference ([`eid-mongolia-sdk-go`](https://github.com/gerege-systems/eid-mongolia-sdk-go)
  `pades`) (checked in CI against golden vectors)
- iOS/macOS version: [`eid-mongolia-sdk-swift`](https://github.com/gerege-systems/eid-mongolia-sdk-swift) — API 1:1

## Install (JitPack)

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.github.gerege-systems:eid-mongolia-sdk-android:0.10.1")
}
```

Version: use the latest tag ([releases](https://github.com/gerege-systems/eid-mongolia-sdk-android/tags)).

## Usage

```kotlin
import mn.eidmongolia.eid.pades.*

// 1) No network: prepare the PDF and produce the DTBS
// with verifyPage = true, fileName is required (otherwise REQUEST_INVALID); the CA registers the first eID signature only together with its page
val prepared = EidPades.prepare(pdf, PrepareOptions(signerCert = signCertDer, verifyPage = true, fileName = "Contract No. 1.pdf"))
// prepared.state can be stored; have prepared.dtbs (32 bytes) signed by the phone/token

// 2) TSA + OCSP/CRL + DSS (suspend — runs on the IO dispatcher)
val done = EidPades.complete(prepared.state, signature)
// done.pdf, done.cms, done.docId, done.outSha256, done.inSha256, done.hasPage, done.pageSha256,
// done.revIndex, done.sigRevSha256, done.priorCmsSha256, done.priorRevisionSha256, done.signerCert, done.fileName,
// done.claimedRole
val body = done.registration(Medium.PHONE, sessionId = sessionId).toJson()
// if medium is omitted it is derived from sessionId: Medium.PHONE if present, otherwise Medium.TOKEN (the CA's pairing). Medium.PHONE without sessionId,
// Medium.TOKEN with sessionId, or a prepare with claimedRole but no onBehalfOf → REQUEST_INVALID (never sent to the CA).
// → the RP backend registers the body with eID AS IS (POST /pdf/signatures)
```

- `prepare`: preliminary checks (encryption, DocMDP P=1, earlier signatures, ≤ 16); for the first eID signature, with
  `verifyPage = true`, a verification (QR) page (`lang`: `mn` default / `en`; NotoSans subset font, OFL),
  the signature revision, signedAttrs (+ `claimedRole`) → DTBS. `verifyPagePosition = "first"` (0.8.0+) — the page becomes
  page 1 of the document (default `"last"`); `SignatureAppearance.page`, `suggestPlacement` and `Placement.page` count pages of
  the input PDF (`PAGE_SPEC.md` §8a, `PLACEMENT_SPEC.md` §1b).
- `complete`: verifies the citizen's signature over the DTBS (RSA PKCS#1 v1.5, ECDSA) → RFC 3161 → CMS → embed →
  OCSP/CRL → DSS revision. `CompleteOptions.transport` — your own HTTP (proxy etc.); the default is HttpURLConnection
  (10 s total deadline, no redirects, ≤ 4 MiB).
- **Visible signature** (optional, Go `APPEARANCE_SPEC.md`): `PrepareOptions(…, appearance = SignatureAppearance(page = 0,
  x = 36.0, y = 36.0, width = 220.0, height = 64.0))` — in pt, from the bottom-left corner of the visible page (after `/Rotate`);
  `page` 0 = the last page of the input that is **not** an eID verify page (verify pages of earlier signatures are skipped;
  `PLACEMENT_SPEC.md` §1a), 1… stay as explicit numbers. Height ≥ 45 pt; if it leaves the page or the text does not fit,
  `REQUEST_INVALID`. null = invisible.
- **Stamp placement** (Go `PLACEMENT_SPEC.md`): `x/y` is the requested position — if it overlaps page content (with a 4 pt margin) it
  moves to the first free position (the mirrored column at the same height → up by 12 pt in the requested column → up in the mirrored column).
  `prepared.placement` (`page`, `x`, `y`, `width`, `height` — pt; `status`: `PlacementStatus.REQUESTED` | `MOVED` |
  `OVERLAP` — no free spot, at the requested position | `UNSCANNED` — the page could not be read within the limits, at the requested position).
  It is advisable to tell the user about `OVERLAP` / `UNSCANNED` — the signature is valid in every case.
- **Citizen-placed stamp** (`PLACEMENT_SPEC.md` §6a/§6b): `EidPades.suggestPlacement(pdf, appearance)` — runs `prepare`'s
  placement algorithm without signature, certificate or network → `PlacementSuggestion` (`page`, `x`, `y`,
  `width`, `height`, `status` = `prepared.placement` for the same input; `pageWidth`, `pageHeight`, `pageCount`, `pages[]`
  (the visible size of each page, in pt; 0×0 if unreadable)). The UI shows the default position in a preview, and passes the position the citizen
  dragged to via `SignatureAppearance(…, exact = true)`: the stamp is drawn exactly there and never moves
  (`status`: `REQUESTED`, or `OVERLAP` if there is content underneath, `UNSCANNED`; never `MOVED`); if it leaves the page,
  `REQUEST_INVALID`. Screen (top-left, `s` px/pt) ↔ appearance: `left = x·s`, `top = (pageHeight − y − height)·s`;
  and back `x = left/s`, `y = pageHeight − top/s − height`. `exact = false` (default) is byte-identical to before.
- `registration(medium, sessionId, onBehalfOf)` — earlier signatures only by `priorCmsSha256` (if both lists are
  sent, the CA returns 400). On 409 `PRIOR_MISMATCH`, move the matching entries of `priorSignatures` into `priorRevisionSha256` and
  resend (assembled at the CA, mode A). `RequestInvalid` if revIndex is 1 without a page, there is no `fileName`, `medium` ↔ `sessionId` conflict (phone requires sessionId, token requires
  none; if `medium` is omitted it is derived from sessionId), or `onBehalfOf` (NTRMN-…) is empty for a prepare with `claimedRole`.
- Structure checks (Go `PRECHECKS.md` #2a/#2b): nesting > 256, ObjStm cycle, `/Extends` > 64, `/Size` > 2^21 →
  `PDF_INVALID` (in `complete` — `STATE_INVALID`).
- Errors: `EidPadesException.code` — stable codes, the same in every SDK (`PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_LOCKED`,
  `PDF_FOREIGN_SIGNATURE`, `SIGNATURE_INVALID`, `TSA_UNAVAILABLE`, `LTV_UNAVAILABLE`, `STATE_INVALID`, …).
  `retryable` — a transient TSA/LTV error (retry with the same state); `LtvUnavailable.certificateRevoked` — a certificate in the chain
  was revoked by an OCSP/CRL signed by its issuer (final — `retryable = false`).
- The library's own manifest adds the `INTERNET` permission.
- There is no full validator in this library — validation is done in the backend with the Go SDK.

Integration documentation: <https://developer.eidmongolia.mn>.

## Conformance

`pades/src/test/resources/golden/` — the Go reference's golden vectors (input PDFs, **test-only** PKI certificates,
fixed TSA/OCSP/CRL responses); private keys removed. The source tag is in `golden/SOURCE`.

```sh
scripts/sync-pades-golden.sh --check     # vendored = the Go repo's tag
./gradlew :pades:testDebugUnitTest       # JVM, no device required
```

## Source and contributions

This repo is a **mirror** of eID Mongolia's internal repo (`sync from ca <sha>` commits). Please file bugs and suggestions in
GitHub Issues; PRs are moved over to the internal repo and applied there.

## License

MIT — [LICENSE](LICENSE). Font: SIL Open Font License 1.1
(`pades/src/main/resources/mn/eidmongolia/eid/pades/fonts/OFL.txt`).
