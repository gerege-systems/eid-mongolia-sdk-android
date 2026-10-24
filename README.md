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
    implementation("com.github.gerege-systems:eid-mongolia-sdk-android:0.10.0")
}
```

Хувилбар: хамгийн сүүлийн tag-ийг ашиглана ([releases](https://github.com/gerege-systems/eid-mongolia-sdk-android/tags)).

## Хэрэглээ

```kotlin
import mn.eidmongolia.eid.pades.*

// 1) Сүлжээгүй: PDF-ийг бэлдэж DTBS гаргана
// verifyPage = true бол fileName заавал (эс бөгөөс REQUEST_INVALID); эхний eID гарын үсгийг CA зөвхөн хуудастай бүртгэнэ
val prepared = EidPades.prepare(pdf, PrepareOptions(signerCert = signCertDer, verifyPage = true, fileName = "Гэрээ №1.pdf"))
// prepared.state-ийг хадгалж болно; prepared.dtbs-ийг (32 байт) утас/токеноор гарын үсэглүүлнэ

// 2) TSA + OCSP/CRL + DSS (suspend — IO dispatcher дээр ажиллана)
val done = EidPades.complete(prepared.state, signature)
// done.pdf, done.cms, done.docId, done.outSha256, done.inSha256, done.hasPage, done.pageSha256,
// done.revIndex, done.sigRevSha256, done.priorCmsSha256, done.priorRevisionSha256, done.signerCert, done.fileName,
// done.claimedRole
val body = done.registration(Medium.PHONE, sessionId = sessionId).toJson()
// medium-ийг орхивол sessionId-аас: байвал Medium.PHONE, үгүй бол Medium.TOKEN (CA-ийн хос). Medium.PHONE + sessionId-гүй,
// Medium.TOKEN + sessionId, эсвэл claimedRole-той prepare + onBehalfOf-гүй → REQUEST_INVALID (CA руу явахгүй).
// → RP backend нь body-г eID-д ЯГ ХЭВЭЭР бүртгэнэ (POST /pdf/signatures)
```

- `prepare`: урьдчилсан шалгуур (шифрлэлт, DocMDP P=1, өмнөх гарын үсэг, ≤ 16), эхний eID гарын үсэгт
  `verifyPage = true` бол баталгаажуулалтын (QR) хуудас (`lang`: `mn` анхдагч / `en`; NotoSans subset фонт, OFL),
  гарын үсгийн revision, signedAttrs (+ `claimedRole`) → DTBS. `verifyPagePosition = "first"` (0.8.0+) — хуудас баримтын
  1-р хуудас болно (анхдагч `"last"`); `SignatureAppearance.page`, `suggestPlacement`, `Placement.page` оролтын PDF-ийн
  хуудсаар тоологдоно (`PAGE_SPEC.md` §8a, `PLACEMENT_SPEC.md` §1b).
- `complete`: иргэний гарын үсгийг DTBS дээр шалгана (RSA PKCS#1 v1.5, ECDSA) → RFC 3161 → CMS → embed →
  OCSP/CRL → DSS revision. `CompleteOptions.transport` — өөрийн HTTP (proxy г.м.); анхдагч нь HttpURLConnection
  (10 с нийт deadline, redirect-гүй, ≤ 4 MiB).
- **Харагдах гарын үсэг** (сонголттой, Go `APPEARANCE_SPEC.md`): `PrepareOptions(…, appearance = SignatureAppearance(page = 0,
  x = 36.0, y = 36.0, width = 220.0, height = 64.0))` — pt, хуудасны харагдах (`/Rotate`-ийн дараах) зүүн доод булангаас;
  `page` 0 = оролтын eID verify хуудас **биш** сүүлийн хуудас (өмнөх гарын үсгүүдийн verify хуудсыг алгасна;
  `PLACEMENT_SPEC.md` §1a), 1… тодорхой дугаар хэвээр. Өндөр ≥ 45 pt; хуудаснаас гарах, бичвэр багтахгүй бол
  `REQUEST_INVALID`. null = үл харагдах.
- **Тамганы байрлал** (Go `PLACEMENT_SPEC.md`): `x/y` нь хүссэн байрлал — хуудасны агуулгатай (4 pt зайтай) давхцвал
  эхний чөлөөт байрлал руу шилжинэ (толин багана ижил өндөрт → хүссэн баганаар 12 pt-ээр дээш → толин баганаар дээш).
  `prepared.placement` (`page`, `x`, `y`, `width`, `height` — pt; `status`: `PlacementStatus.REQUESTED` | `MOVED` |
  `OVERLAP` — чөлөөт газар алга, хүссэн байрлалд | `UNSCANNED` — хуудсыг хязгаарт уншиж чадсангүй, хүссэн байрлалд).
  `OVERLAP` / `UNSCANNED`-ийг хэрэглэгчид мэдэгдэх нь зүйтэй — гарын үсэг аль ч тохиолдолд хүчинтэй.
- **Иргэн өөрөө байрлуулах** (`PLACEMENT_SPEC.md` §6a/§6b): `EidPades.suggestPlacement(pdf, appearance)` — гарын үсэг,
  сертификат, сүлжээгүйгээр `prepare`-ийн байрлалын алгоритмыг ажиллуулна → `PlacementSuggestion` (`page`, `x`, `y`,
  `width`, `height`, `status` = ижил оролтод `prepared.placement`; `pageWidth`, `pageHeight`, `pageCount`, `pages[]`
  (хуудас бүрийн харагдах хэмжээ, pt; уншигдахгүй бол 0×0)). UI урьдчилан харахад анхдагч байрлалыг үзүүлж, иргэн
  чирсэн байрлалыг `SignatureAppearance(…, exact = true)`-аар өгнө: тамга яг тэнд зурагдана, хэзээ ч шилжихгүй
  (`status`: `REQUESTED` эсвэл агуулга дээр бол `OVERLAP`, `UNSCANNED`; `MOVED` хэзээ ч үгүй); хуудаснаас гарвал
  `REQUEST_INVALID`. Дэлгэцийн (зүүн дээд, `s` px/pt) ↔ appearance: `left = x·s`, `top = (pageHeight − y − height)·s`;
  буцаад `x = left/s`, `y = pageHeight − top/s − height`. `exact = false` (анхдагч) өмнөхтэй байт-ижил.
- `registration(medium, sessionId, onBehalfOf)` — өмнөх гарын үсгүүдийг зөвхөн `priorCmsSha256`-аар (хоёр жагсаалтыг
  зэрэг илгээвэл CA 400). 409 `PRIOR_MISMATCH` бол `priorSignatures`-ийн тохирохыг `priorRevisionSha256` руу шилжүүлж
  дахин илгээнэ (CA угсарсан, горим A). revIndex 1 хуудасгүй, `fileName`-гүй, `medium` ↔ `sessionId` зөрчилтэй (phone-д sessionId заавал, token-д
  алга; `medium` орхивол sessionId-аас), эсвэл `claimedRole`-той prepare-д `onBehalfOf` (NTRMN-…) хоосон бол `RequestInvalid`.
- Бүтцийн шалгалт (Go `PRECHECKS.md` #2a/#2b): давхарлалт > 256, ObjStm мөчлөг, `/Extends` > 64, `/Size` > 2^21 →
  `PDF_INVALID` (`complete`-д — `STATE_INVALID`).
- Алдаа: `EidPadesException.code` — бүх SDK-д ижил тогтвортой код (`PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_LOCKED`,
  `PDF_FOREIGN_SIGNATURE`, `SIGNATURE_INVALID`, `TSA_UNAVAILABLE`, `LTV_UNAVAILABLE`, `STATE_INVALID`, …).
  `retryable` — TSA/LTV түр алдаа (ижил state-ээр дахин); `LtvUnavailable.certificateRevoked` — гинжийн гэрчилгээ
  олгогчийн гарын үсэгтэй OCSP/CRL-ээр цуцлагдсан (эцсийн — `retryable = false`).
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
`implementation("com.github.gerege-systems:eid-mongolia-sdk-android:0.10.0")` (use the latest tag). This repository is a read-only mirror;
please file issues here.
