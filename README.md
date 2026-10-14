# eID Mongolia — PAdES SDK (Android)

`mn.eidmongolia.eid.pades` — eID Mongolia-ийн **client-side PAdES** (PDF гарын үсэг) Kotlin сан. PDF хэзээ ч eID
сервер рүү явахгүй: апп PDF-ийг локалд бэлдэж (`prepare`), зөвхөн 32 байт DTBS-ийг иргэний утас эсвэл USB токеноор
гарын үсэглүүлээд, гарын үсгийг PDF-д суулгана (`complete`: RFC 3161 цагийн тамга + OCSP/CRL + DSS → PAdES B-LT).

- Android minSdk 24, JDK 17
- Native library, BouncyCastle байхгүй — `java.security` + жижиг DER writer; хамаарал нь зөвхөн kotlinx-coroutines
- Профайл `pades-client/1` — Go reference ([`eid-mongolia-sdk-go`](https://github.com/gerege-systems/eid-mongolia-sdk-go)
  `pades`)-тэй **байт-ижил** гаралт (golden vector-оор CI-д шалгагдана)
- iOS/macOS хувилбар: [`eid-mongolia-sdk-swift`](https://github.com/gerege-systems/eid-mongolia-sdk-swift) — API 1:1

## Суулгах (JitPack)

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
    implementation("com.github.gerege-systems:eid-mongolia-sdk-android:0.1.0")
}
```

## Хэрэглээ

```kotlin
import mn.eidmongolia.eid.pades.*

// 1) Сүлжээгүй: PDF-ийг бэлдэж DTBS гаргана
val prepared = EidPades.prepare(pdf, PrepareOptions(signerCert = signCertDer, verifyPage = true))
// prepared.state-ийг хадгалж болно; prepared.dtbs-ийг (32 байт) утас/токеноор гарын үсэглүүлнэ

// 2) TSA + OCSP/CRL + DSS (suspend — IO dispatcher дээр ажиллана)
val done = EidPades.complete(prepared.state, signature)
// done.pdf, done.cms, done.docId, done.outSha256, done.inSha256, done.hasPage, done.pageSha256,
// done.revIndex, done.sigRevSha256, done.priorCmsSha256, done.signerCert
// → RP backend нь гарын үсгийг eID-д бүртгэнэ (POST /pdf/signatures)
```

- `prepare`: урьдчилсан шалгуур (шифрлэлт, DocMDP P=1, өмнөх гарын үсэг, ≤ 16), эхний eID гарын үсэгт
  `verifyPage = true` бол баталгаажуулалтын (QR) хуудас (`lang`: `mn` анхдагч / `en`; NotoSans subset фонт, OFL),
  гарын үсгийн revision, signedAttrs (+ `claimedRole`) → DTBS.
- `complete`: иргэний гарын үсгийг DTBS дээр шалгана (RSA PKCS#1 v1.5, ECDSA) → RFC 3161 → CMS → embed →
  OCSP/CRL → DSS revision. `CompleteOptions.transport` — өөрийн HTTP (proxy г.м.).
- Алдаа: `EidPadesException.code` — бүх SDK-д ижил тогтвортой код (`PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_LOCKED`,
  `PDF_FOREIGN_SIGNATURE`, `SIGNATURE_INVALID`, `TSA_UNAVAILABLE`, `LTV_UNAVAILABLE`, `STATE_INVALID`, …).
- `INTERNET` зөвшөөрлийг сангийн manifest өөрөө нэмнэ.
- Бүрэн validator энэ санд байхгүй — шалгалтыг backend-д Go SDK-ээр хийнэ.

Интеграцийн баримт: <https://developer.eidmongolia.mn>.

## Conformance

`pades/src/test/resources/golden/` — Go reference-ийн golden vector (оролтын PDF, **зөвхөн тестийн** PKI гэрчилгээ,
тогтмол TSA/OCSP/CRL хариу); хувийн түлхүүр хасагдсан. Эх tag нь `golden/SOURCE`-д.

```sh
scripts/sync-pades-golden.sh --check     # vendored = Go репогийн tag
./gradlew :pades:testDebugUnitTest       # JVM, төхөөрөмж шаардахгүй
```

## Эх сурвалж ба хувь нэмэр

Энэ репо нь eID Mongolia-ийн дотоод репоны **толин хуулбар** (`sync from ca <sha>` commit-ууд). Алдаа, санал бол
GitHub Issues-д бичнэ үү; PR-ийг дотоод репод шилжүүлж оруулна.

## License

MIT — [LICENSE](LICENSE). Фонт: SIL Open Font License 1.1
(`pades/src/main/resources/mn/eidmongolia/eid/pades/fonts/OFL.txt`).

---

### English

Client-side PAdES signing for eID Mongolia (Kotlin, Android minSdk 24). The PDF never leaves the device: `prepare`
returns a 32-byte DTBS to be signed by the citizen's phone or USB token; `complete` embeds the signature with an
RFC 3161 timestamp, OCSP/CRL and DSS (PAdES B-LT). Output is byte-identical to the Go reference
(`gerege-systems/eid-mongolia-sdk-go`, profile `pades-client/1`), enforced by golden vectors in CI. Install from
JitPack: add `maven("https://jitpack.io")` and
`implementation("com.github.gerege-systems:eid-mongolia-sdk-android:0.1.0")`. This repository is a read-only mirror;
please file issues here.
