# android-exposure-auditor

Static auditor for the **zero-permission Android attack surface** — the
missing-authorization (CWE-862) class that lets *any* installed app reach a
component it shouldn't.

It parses an `AndroidManifest.xml` and flags exported components that ship
without an authorization guard: the same pattern behind a number of my
rewarded findings in the **Samsung Mobile Security Rewards Program**.

> Pure Python standard library. No dependencies. One file.

## Why this exists

Most Android privilege issues don't need a memory-corruption exploit — they
need a component that was left reachable by other apps with no permission
check. Exported activities, broadcast receivers, services, and content
providers that trust caller-supplied state are a large, under-audited surface.

This tool encodes that hunt as a fast first pass:

- **Exported components without a permission guard** → `CWE-862`
- **Implicitly exported components** (intent-filter present, no explicit
  `android:exported`) — historically default-true and easy to miss
- **Content providers** exported with no read/write permission → `CWE-862`,
  and risky `grantUriPermissions` exposure → `CWE-926`
- **Browsable deep links** (`VIEW` + `BROWSABLE` + scheme) reachable
  zero-permission — the classic deep-link hijack / state-replay surface

## Usage

```bash
python3 android_exposure_auditor.py path/to/AndroidManifest.xml

# machine-readable
python3 android_exposure_auditor.py AndroidManifest.xml --json

# gate on severity (useful in CI; exits non-zero when findings remain)
python3 android_exposure_auditor.py AndroidManifest.xml --min-severity medium
```

Extract a manifest from an APK first with any standard tool
(`apktool d app.apk`, or `aapt2 dump xmltree app.apk --file AndroidManifest.xml`).

## Example

```
$ python3 android_exposure_auditor.py examples/vulnerable_AndroidManifest.xml

7 potential exposure(s) found:

[HIGH] CWE-862  ContentProvider exported without permission
        component: .GalleryProvider (provider)
        Any installed app can query/insert/update/delete through this provider.

[MEDIUM] CWE-862  Browsable deep link reachable zero-permission
        component: .DeepLinkActivity (activity)
        A web page or another app can drive this component via a demoapp: link.

[MEDIUM] CWE-862  receiver implicitly exported without permission guard
        component: .StateReceiver (receiver)
        ...
```

A deliberately-vulnerable sample lives in [`examples/`](examples/).

## Field-tested pattern

The detections here mirror real, **rewarded** Samsung Mobile Security findings
of mine (CWE-862 cluster):

- FMM deep-link device-unlock state replay (CWE-862 / CWE-294)
- Samsung Pass exported-receiver leak (CWE-862)
- DigitalKey Car-Key AIDL reachable zero-permission (CWE-862)

This repository contains **no vulnerability details** for unpatched issues —
only the generic detection methodology.

## Roadmap

- [ ] Decompiled-code cross-check (does the exported component actually act on caller input?)
- [ ] Android 12+ `exported` requirement awareness + `minSdkVersion` context
- [ ] `permissionGroup` / `protectionLevel` resolution (signature vs normal vs dangerous)
- [ ] Batch mode over a directory of manifests
- [ ] SARIF output for CI security dashboards

## Author

Douglas Guedes — security researcher (zero-permission / zero-click Android attack surface).

- X: [@Douglaspguedes](https://x.com/Douglaspguedes)
- Bugcrowd: [douglasninjaguedes](https://bugcrowd.com/douglasninjaguedes)

## License

MIT — see [LICENSE](LICENSE).
