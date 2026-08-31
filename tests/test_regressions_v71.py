from __future__ import annotations

import importlib.util
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "safewebheaders.py"
SPEC = importlib.util.spec_from_file_location("safewebheaders_v71", SCRIPT)
assert SPEC and SPEC.loader
swh = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = swh
SPEC.loader.exec_module(swh)


def snapshot(
    url: str = "https://example.test/",
    status_code: int = 200,
    **headers: str | list[str],
) -> swh.ResponseSnapshot:
    normalized: dict[str, list[str]] = {}
    for name, value in headers.items():
        normalized[swh.normalize_header_name(name)] = (
            list(value) if isinstance(value, list) else [value]
        )
    return swh.ResponseSnapshot(
        url=url,
        status_code=status_code,
        reason="OK",
        headers=normalized,
        display_names={key: swh.canonical_header(key) for key in normalized},
        elapsed_ms=1,
    )


def report_from_snapshot(
    snap: swh.ResponseSnapshot, findings: list[swh.Finding]
) -> swh.ScanReport:
    return swh.ScanReport(
        tool="SafeWebHeaders",
        version=swh.VERSION,
        timestamp="2026-08-12T12:00:00-05:00",
        requested_url=snap.url,
        final_url=snap.url,
        method="GET",
        status_code=snap.status_code,
        reason=snap.reason,
        profile="web",
        tls_verification="activa",
        elapsed_ms=1,
        redirect_following=False,
        redirects=[],
        excluded_headers=[],
        findings=findings,
        response_headers=snap.headers,
        display_names=snap.display_names,
        show_headers=False,
        resolved_ips=["192.0.2.10"],
    )


class RawHeaders:
    """Colección mínima que conserva variantes de casing para el extractor."""

    def __init__(self, pairs: list[tuple[str, list[str]]]) -> None:
        self.pairs = pairs

    def keys(self) -> list[str]:
        return [name for name, _ in self.pairs]

    def __iter__(self):
        return iter(self.keys())

    def getlist(self, name: str) -> list[str]:
        return next(values for candidate, values in self.pairs if candidate == name)

    def get(self, name: str):
        values = self.getlist(name)
        return values[0] if values else None


def extract(pairs: list[tuple[str, list[str]]]):
    response = SimpleNamespace(
        raw=SimpleNamespace(headers=RawHeaders(pairs)),
        headers={},
    )
    return swh.extract_response_headers(response)


class HeaderNameCaseTests(unittest.TestCase):
    def test_xfo_name_accepts_upper_lower_canonical_and_mixed_case(self) -> None:
        spellings = (
            "X-Frame-Options",
            "x-frame-options",
            "X-FRAME-OPTIONS",
            "x-FrAmE-oPtIoNs",
        )
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                headers, display_names = extract([(spelling, ["dEnY"])])
                snap = swh.ResponseSnapshot(
                    url="https://example.test/",
                    status_code=200,
                    reason="OK",
                    headers=headers,
                    display_names=display_names,
                )
                finding = swh.analyze_x_frame_options(snap, set(), "web")[0]
                self.assertEqual(headers["x-frame-options"], ["dEnY"])
                self.assertEqual(finding.header, "X-Frame-Options")
                self.assertEqual(finding.status, "correcta")

    def test_mixed_case_names_work_for_the_core_baseline(self) -> None:
        headers, display_names = extract(
            [
                ("STRICT-TRANSPORT-SECURITY", ["MAX-AGE=63072000; includeSubDomains"]),
                ("x-content-TYPE-options", ["NoSnIfF"]),
                ("CONTENT-type", ["text/html; charset=UTF-8"]),
                ("rEfErReR-PoLiCy", ["strict-origin-when-cross-origin"]),
                (
                    "CoNtEnT-SeCuRiTy-PoLiCy",
                    [
                        (
                            "default-src 'self'; object-src 'none'; base-uri 'none'; "
                            "frame-ancestors 'none'; form-action 'self'"
                        )
                    ],
                ),
                ("x-FrAmE-oPtIoNs", ["SAMEORIGIN"]),
            ]
        )
        snap = swh.ResponseSnapshot(
            url="https://example.test/",
            status_code=200,
            reason="OK",
            headers=headers,
            display_names=display_names,
        )
        self.assertTrue(
            {
                "strict-transport-security",
                "x-content-type-options",
                "content-type",
                "referrer-policy",
                "content-security-policy",
                "x-frame-options",
            }.issubset(headers)
        )
        self.assertEqual(swh.analyze_hsts(snap, set())[0].status, "correcta")
        self.assertEqual(
            swh.analyze_x_content_type_options(snap, set())[0].status, "correcta"
        )
        self.assertEqual(
            swh.analyze_x_frame_options(snap, set(), "web")[0].status, "correcta"
        )

    def test_case_variants_of_same_name_are_detected_as_duplicates(self) -> None:
        headers, display_names = extract(
            [
                ("X-Frame-Options", ["DENY"]),
                ("x-frame-options", ["SAMEORIGIN"]),
            ]
        )
        snap = swh.ResponseSnapshot(
            url="https://example.test/",
            status_code=200,
            reason="OK",
            headers=headers,
            display_names=display_names,
        )
        finding = swh.analyze_x_frame_options(snap, set(), "web")[0]
        self.assertEqual(headers["x-frame-options"], ["DENY", "SAMEORIGIN"])
        self.assertEqual(finding.status, "incorrecta")
        self.assertIn("varios", finding.title.lower())

    def test_cli_aliases_are_not_treated_as_real_response_header_names(self) -> None:
        headers, display_names = extract(
            [("XFO", ["DENY"]), ("HSTS", ["max-age=63072000"])]
        )
        snap = swh.ResponseSnapshot(
            url="https://example.test/",
            status_code=200,
            reason="OK",
            headers=headers,
            display_names=display_names,
        )
        self.assertIn("xfo", headers)
        self.assertIn("hsts", headers)
        self.assertFalse(snap.has("X-Frame-Options"))
        self.assertFalse(snap.has("Strict-Transport-Security"))

    def test_underscore_does_not_equal_hyphen_in_observed_http_name(self) -> None:
        headers, display_names = extract([("X_FRAME_OPTIONS", ["DENY"])])
        snap = swh.ResponseSnapshot(
            url="https://example.test/",
            status_code=200,
            reason="OK",
            headers=headers,
            display_names=display_names,
        )
        self.assertIn("x_frame_options", headers)
        self.assertFalse(snap.has("X-Frame-Options"))


class CaseHeaderHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("cOnTeNt-TyPe", "text/html; charset=UTF-8")
        if self.path == "/duplicate":
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("x-frame-options", "SAMEORIGIN")
        else:
            self.send_header("x-FrAmE-oPtIoNs", "dEnY")
        self.end_headers()
        self.wfile.write(b"<!doctype html><title>case test</title>")

    def log_message(self, _format: str, *_args) -> None:
        return


class HeaderNameCaseIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CaseHeaderHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_real_http_response_with_mixed_case_name_is_detected(self) -> None:
        response = swh.requests.get(f"{self.base}/single", timeout=3, stream=True)
        try:
            snap = swh.snapshot_response(response)
        finally:
            response.close()
        self.assertTrue(snap.has("X-FRAME-OPTIONS"))
        finding = swh.analyze_x_frame_options(snap, set(), "web")[0]
        self.assertEqual(finding.status, "correcta")

    def test_real_http_case_variants_are_preserved_as_duplicates(self) -> None:
        response = swh.requests.get(f"{self.base}/duplicate", timeout=3, stream=True)
        try:
            snap = swh.snapshot_response(response)
        finally:
            response.close()
        self.assertEqual(snap.all("x-frame-options"), ["DENY", "SAMEORIGIN"])
        finding = swh.analyze_x_frame_options(snap, set(), "web")[0]
        self.assertEqual(finding.status, "incorrecta")


class ContextualAbsenceTests(unittest.TestCase):
    OPTIONAL: ClassVar[set[str]] = {
        "Cache-Control",
        "Clear-Site-Data",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
        "X-DNS-Prefetch-Control",
        "X-Permitted-Cross-Domain-Policies",
        "Integrity-Policy",
        "Permissions-Policy",
    }

    def test_empty_contextual_analyzer_emits_nothing(self) -> None:
        self.assertEqual(swh.analyze_contextual_response_headers(snapshot(), set()), [])

    def test_full_scan_does_not_list_absent_optional_headers(self) -> None:
        snap = snapshot(Content_Type="text/html; charset=UTF-8")
        findings = swh.run_analysis(
            snap,
            snapshots=[snap],
            excluded=set(),
            profile="web",
            follow_redirects=False,
            essential_only=False,
        )
        names = {item.header for item in findings}
        self.assertTrue(self.OPTIONAL.isdisjoint(names))

    def test_console_and_structured_categories_omit_absent_optional_headers(
        self,
    ) -> None:
        snap = snapshot(Content_Type="text/html; charset=UTF-8")
        findings = swh.run_analysis(
            snap,
            snapshots=[snap],
            excluded=set(),
            profile="web",
            follow_redirects=False,
        )
        report = report_from_snapshot(snap, findings)
        rendered = swh.render_console(report, color=False, reveal_sensitive=False)
        serialized = report.to_dict()
        serialized_headers = {
            finding["header"]
            for category in serialized["categories"]
            for finding in category["findings"]
        }
        for header in self.OPTIONAL:
            self.assertNotIn(header, rendered)
            self.assertNotIn(header, serialized_headers)

    def test_present_contextual_headers_are_still_validated(self) -> None:
        snap = snapshot(
            Permissions_Policy="camera=(), microphone=()",
            Clear_Site_Data='"cache", "cookies"',
            X_DNS_Prefetch_Control="off",
            Cross_Origin_Opener_Policy="same-origin",
        )
        findings = swh.run_analysis(
            snap,
            snapshots=[snap],
            excluded=set(),
            profile="web",
            follow_redirects=False,
            essential_only=False,
        )
        names = {item.header for item in findings}
        self.assertIn("Permissions-Policy", names)
        self.assertIn("Clear-Site-Data", names)
        self.assertIn("X-DNS-Prefetch-Control", names)
        self.assertIn("Cross-Origin-Opener-Policy", names)

    def test_cache_control_absence_requires_explicit_sensitive_context(self) -> None:
        findings = swh.analyze_contextual_response_headers(
            snapshot(), set(), sensitive_response=True
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].header, "Cache-Control")
        self.assertEqual(findings[0].status, "ausente")


class XFrameOptionsCriterionTests(unittest.TestCase):
    def test_deny_is_effective_not_obsolete(self) -> None:
        finding = swh.analyze_x_frame_options(
            snapshot(X_Frame_Options="DENY"), set(), "web"
        )[0]
        self.assertEqual(finding.status, "correcta")
        self.assertNotEqual(finding.category, "obsoletas")
        criterion = swh.finding_criterion(finding)
        self.assertIn("IANA", criterion)
        self.assertIn("ALLOW-FROM", criterion)

    def test_allow_from_is_the_obsolete_directive(self) -> None:
        finding = swh.analyze_x_frame_options(
            snapshot(X_Frame_Options="allow-from https://portal.test"), set(), "web"
        )[0]
        self.assertEqual(finding.category, "obsoletas")

    def test_similar_unknown_token_is_not_mislabelled_allow_from(self) -> None:
        finding = swh.analyze_x_frame_options(
            snapshot(X_Frame_Options="ALLOW-FROMMALFORMED"), set(), "web"
        )[0]
        self.assertEqual(finding.category, "incorrectas")
        self.assertEqual(finding.status, "incorrecta")

    def test_missing_xfo_is_not_reported_on_redirect_response(self) -> None:
        self.assertEqual(
            swh.analyze_x_frame_options(snapshot(status_code=302), set(), "web"), []
        )


if __name__ == "__main__":
    unittest.main()
