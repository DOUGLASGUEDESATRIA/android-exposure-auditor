#!/usr/bin/env python3
"""
android-exposure-auditor — static auditor for Android attack surface.

Parses an AndroidManifest.xml and flags components that are reachable by other
apps without an authorization guard — the missing-authorization (CWE-862) class
that underpins most zero-permission Android privilege issues.

Detections:
  - Exported activities / services / receivers without an android:permission guard
  - Content providers exported without read/write permission (and risky
    grantUriPermissions exposure)
  - Implicitly-exported components (intent-filter present, no explicit
    android:exported) — historically default-true and easy to miss
  - Browsable deep links (VIEW + BROWSABLE + data scheme) reachable
    zero-permission — the classic deep-link hijack / state-replay surface

Usage:
    python android_exposure_auditor.py path/to/AndroidManifest.xml
    python android_exposure_auditor.py AndroidManifest.xml --json
    python android_exposure_auditor.py AndroidManifest.xml --min-severity medium

Pure standard library. No third-party dependencies.
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Iterable

ANDROID_NS = "http://schemas.android.com/apk/res/android"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def attr(el: ET.Element, name: str) -> str | None:
    """Read an android:-namespaced attribute regardless of prefix resolution."""
    return el.get(f"{{{ANDROID_NS}}}{name}") or el.get(name)


def as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() == "true"


@dataclass
class Finding:
    component: str
    kind: str
    severity: str
    cwe: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)


def _has_browsable_deeplink(component: ET.Element) -> dict | None:
    """Return deep-link evidence if the component exposes a browsable VIEW link."""
    for ifilter in component.findall("intent-filter"):
        actions = {attr(a, "name") for a in ifilter.findall("action")}
        categories = {attr(c, "name") for c in ifilter.findall("category")}
        if "android.intent.action.VIEW" not in actions:
            continue
        if "android.intent.category.BROWSABLE" not in categories:
            continue
        schemes = sorted(
            {attr(d, "scheme") for d in ifilter.findall("data") if attr(d, "scheme")}
        )
        hosts = sorted(
            {attr(d, "host") for d in ifilter.findall("data") if attr(d, "host")}
        )
        if schemes:
            return {"schemes": schemes, "hosts": hosts}
    return None


def _is_exported(component: ET.Element) -> tuple[bool, bool]:
    """
    Return (exported, implicit).
    `implicit` is True when exported was inferred from an intent-filter rather
    than an explicit android:exported attribute.
    """
    explicit = as_bool(attr(component, "exported"))
    if explicit is not None:
        return explicit, False
    # No explicit flag: a component with an intent-filter has historically
    # defaulted to exported=true. Worth surfacing because it is easy to miss.
    has_filter = component.find("intent-filter") is not None
    return has_filter, has_filter


def audit_component(tag: str, component: ET.Element) -> Iterable[Finding]:
    name = attr(component, "name") or "(unnamed)"
    exported, implicit = _is_exported(component)
    if not exported:
        return

    export_word = "implicitly exported" if implicit else "exported"
    permission = attr(component, "permission")

    if tag == "provider":
        read_p = attr(component, "readPermission")
        write_p = attr(component, "writePermission")
        grants = as_bool(attr(component, "grantUriPermissions"))
        if not (permission or read_p or write_p):
            yield Finding(
                component=name,
                kind="provider",
                severity="high",
                cwe="CWE-862",
                title=f"ContentProvider {export_word} without permission",
                detail=(
                    "Any installed app can query/insert/update/delete through "
                    "this provider — no read/write permission is declared."
                ),
                evidence={"exported": exported, "implicit": implicit},
            )
        if grants:
            yield Finding(
                component=name,
                kind="provider",
                severity="medium",
                cwe="CWE-926",
                title="Provider grants URI permissions",
                detail=(
                    "grantUriPermissions=true lets callers be handed temporary "
                    "access to arbitrary URIs — review for confused-deputy reads."
                ),
                evidence={"grantUriPermissions": True},
            )
        return

    # activity / activity-alias / service / receiver
    if not permission:
        sev = {"receiver": "medium", "service": "medium"}.get(tag, "low")
        yield Finding(
            component=name,
            kind=tag,
            severity=sev,
            cwe="CWE-862",
            title=f"{tag} {export_word} without permission guard",
            detail=(
                "Reachable by any app via Intent. Confirm the component performs "
                "no privileged action and trusts no caller-supplied state."
            ),
            evidence={"exported": exported, "implicit": implicit},
        )

    deeplink = _has_browsable_deeplink(component)
    if deeplink and not permission:
        yield Finding(
            component=name,
            kind=tag,
            severity="medium",
            cwe="CWE-862",
            title="Browsable deep link reachable zero-permission",
            detail=(
                "A web page or another app can drive this component via a "
                f"{'/'.join(deeplink['schemes'])}: link. Classic deep-link "
                "hijack / state-replay surface — validate every parameter."
            ),
            evidence=deeplink,
        )


def audit_manifest(path: str) -> list[Finding]:
    tree = ET.parse(path)
    root = tree.getroot()
    app = root.find("application")
    if app is None:
        return []
    findings: list[Finding] = []
    for tag in COMPONENT_TAGS:
        for component in app.findall(tag):
            findings.extend(audit_component(tag, component))
    findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    return findings


def format_table(findings: list[Finding]) -> str:
    if not findings:
        return "No exposed-without-guard components found. ✓"
    lines = [f"\n{len(findings)} potential exposure(s) found:\n"]
    colors = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
    reset = "\033[0m"
    use_color = sys.stdout.isatty()
    for f in findings:
        tag = f.severity.upper()
        if use_color:
            tag = f"{colors.get(f.severity, '')}{tag}{reset}"
        lines.append(f"[{tag}] {f.cwe}  {f.title}")
        lines.append(f"        component: {f.component} ({f.kind})")
        lines.append(f"        {f.detail}")
        if f.evidence:
            lines.append(f"        evidence: {json.dumps(f.evidence)}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit an AndroidManifest.xml for zero-permission attack surface (CWE-862)."
    )
    parser.add_argument("manifest", help="path to AndroidManifest.xml")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument(
        "--min-severity",
        choices=list(SEVERITY_ORDER),
        default="low",
        help="only report findings at or above this severity",
    )
    args = parser.parse_args(argv)

    try:
        findings = audit_manifest(args.manifest)
    except FileNotFoundError:
        print(f"error: file not found: {args.manifest}", file=sys.stderr)
        return 2
    except ET.ParseError as exc:
        print(f"error: could not parse manifest: {exc}", file=sys.stderr)
        return 2

    threshold = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(format_table(findings))

    # Non-zero exit when something was flagged — handy in CI.
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
