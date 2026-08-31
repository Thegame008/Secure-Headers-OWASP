from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "safewebheaders.py"
SPEC = importlib.util.spec_from_file_location("safewebheaders_v6", SCRIPT)
assert SPEC and SPEC.loader
swh = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = swh
SPEC.loader.exec_module(swh)


def snapshot(
    url: str = "https://example.test/", **headers: str | list[str]
) -> swh.ResponseSnapshot:
    normalized: dict[str, list[str]] = {}
    for name, value in headers.items():
        normalized[swh.normalize_header_name(name)] = (
            list(value) if isinstance(value, list) else [value]
        )
    return swh.ResponseSnapshot(
        url=url,
        status_code=200,
        reason="OK",
        headers=normalized,
        display_names={key: swh.canonical_header(key) for key in normalized},
        elapsed_ms=4,
    )


def report_from_snapshot(
    snap: swh.ResponseSnapshot, findings: list[swh.Finding] | None = None
) -> swh.ScanReport:
    return swh.ScanReport(
        tool="SafeWebHeaders",
        version=swh.VERSION,
        timestamp="2026-08-11T18:04:22-05:00",
        requested_url=snap.url,
        final_url=snap.url,
        method="GET",
        status_code=snap.status_code,
        reason=snap.reason,
        profile="web",
        tls_verification="activa",
        elapsed_ms=snap.elapsed_ms,
        redirect_following=False,
        redirects=[],
        excluded_headers=[],
        findings=findings or [],
        response_headers=snap.headers,
        display_names=snap.display_names,
        show_headers=False,
    )


class CliRegressionTests(unittest.TestCase):
    def test_plural_exclude_headers_is_accepted(self) -> None:
        args = swh.build_parser().parse_args(
            ["https://example.test", "--exclude-headers", "Referrer-Policy"]
        )
        self.assertEqual(swh.parse_exclusions(args.exclude_header), {"referrer-policy"})

    def test_singular_exclusion_works_after_url(self) -> None:
        args = swh.build_parser().parse_args(
            ["https://example.test", "--exclude-header", "Strict-Transport-Security"]
        )
        self.assertEqual(
            swh.parse_exclusions(args.exclude_header), {"strict-transport-security"}
        )

    def test_plural_exclusion_accepts_equals_syntax(self) -> None:
        args = swh.build_parser().parse_args(
            ["--exclude-headers=HSTS,CSP,Referrer-Policy", "https://example.test"]
        )
        self.assertEqual(
            swh.parse_exclusions(args.exclude_header),
            {
                "strict-transport-security",
                "content-security-policy",
                "referrer-policy",
            },
        )

    def test_repeated_and_comma_exclusions_can_be_combined(self) -> None:
        args = swh.build_parser().parse_args(
            [
                "https://example.test",
                "--exclude-header",
                "HSTS,XFO",
                "--exclude-headers",
                "Server",
            ]
        )
        self.assertEqual(
            swh.parse_exclusions(args.exclude_header),
            {"strict-transport-security", "x-frame-options", "server"},
        )

    def test_excluded_referrer_policy_has_no_visible_finding(self) -> None:
        snap = snapshot(Referrer_Policy="unsafe-url")
        excluded = {"referrer-policy"}
        findings = swh.analyze_referrer_policy(snap, excluded, "web")
        report = report_from_snapshot(snap, findings)
        groups = swh.build_display_groups(report)
        self.assertFalse(any(groups.values()))

    def test_help_documents_production_names_and_compact_exclusions(self) -> None:
        help_text = swh.build_parser().format_help()
        self.assertIn("--analyze-csp", help_text)
        self.assertIn("--response-type", help_text)
        self.assertIn("--timeout SEGUNDOS", help_text)
        self.assertIn("--value-cookie", help_text)
        self.assertIn("separados por coma", help_text)
        self.assertNotIn("--list-excludable-headers", help_text)
        self.assertNotIn("--max-redirects", help_text)

    def test_value_cookies_plural_alias(self) -> None:
        args = swh.build_parser().parse_args(
            ["https://example.test", "--value-cookies"]
        )
        self.assertTrue(args.value_cookie)

    def test_all_cookie_aliases_have_same_destination(self) -> None:
        parser = swh.build_parser()
        for option in ("--value-cookie", "--value-cookies", "--check-cookies"):
            with self.subTest(option=option):
                self.assertTrue(
                    parser.parse_args(["https://example.test", option]).value_cookie
                )

    def test_help_documents_all_poc_modes(self) -> None:
        help_text = swh.build_parser().format_help()
        for option in ("--poc-frame", "--poc-cors", "--poc-csp", "--poc-origin"):
            self.assertIn(option, help_text)

    def test_invalid_poc_origin_with_path_is_rejected(self) -> None:
        args = swh.build_parser().parse_args(
            [
                "https://example.test",
                "--poc-cors",
                "--poc-origin",
                "http://127.0.0.1:8000/ruta",
            ]
        )
        with self.assertRaisesRegex(swh.ScanError, "sin ruta"):
            swh.validate_args(args)

    def test_invalid_poc_origin_brackets_raise_clean_scan_error(self) -> None:
        args = swh.build_parser().parse_args(
            [
                "https://example.test",
                "--poc-cors",
                "--poc-origin",
                "http://[::1:8000",
            ]
        )
        with self.assertRaisesRegex(swh.ScanError, "host o puerto inválido"):
            swh.validate_args(args)

    def test_poc_origin_trailing_slash_is_normalized(self) -> None:
        args = swh.build_parser().parse_args(
            [
                "https://example.test",
                "--poc-cors",
                "--poc-origin",
                "HTTP://LOCALHOST:8000/",
            ]
        )
        swh.validate_args(args)
        self.assertEqual(args.poc_origin, "http://localhost:8000")

    def test_poc_origin_removes_default_http_port_like_browser_origin(self) -> None:
        args = swh.build_parser().parse_args(
            [
                "https://example.test",
                "--poc-cors",
                "--poc-origin",
                "http://LOCALHOST:80",
            ]
        )
        swh.validate_args(args)
        self.assertEqual(args.poc_origin, "http://localhost")

    def test_poc_origin_removes_default_https_port(self) -> None:
        args = swh.build_parser().parse_args(
            [
                "https://example.test",
                "--poc-cors",
                "--poc-origin",
                "https://POC.example:443",
            ]
        )
        swh.validate_args(args)
        self.assertEqual(args.poc_origin, "https://poc.example")

    def test_poc_origin_preserves_ipv6_brackets(self) -> None:
        args = swh.build_parser().parse_args(
            [
                "https://example.test",
                "--poc-cors",
                "--poc-origin",
                "http://[::1]:8000",
            ]
        )
        swh.validate_args(args)
        self.assertEqual(args.poc_origin, "http://[::1]:8000")

    def test_offline_csp_allows_csp_poc(self) -> None:
        args = swh.build_parser().parse_args(
            ["--csp-policy", "default-src 'self'", "--poc-csp"]
        )
        swh.validate_args(args)

    def test_offline_csp_rejects_frame_poc(self) -> None:
        args = swh.build_parser().parse_args(
            ["--csp-policy", "default-src 'self'", "--poc-frame"]
        )
        with self.assertRaisesRegex(swh.ScanError, "contextuales de red"):
            swh.validate_args(args)


class HstsVerdictTests(unittest.TestCase):
    def verdict(self, value: str) -> swh.Finding:
        findings = swh.analyze_hsts(snapshot(Strict_Transport_Security=value), set())
        self.assertEqual(len(findings), 1)
        return findings[0]

    def test_user_case_is_one_incorrect_verdict(self) -> None:
        item = self.verdict("max-age=31536000")
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("falta includeSubDomains", item.evidence)
        self.assertIn("63072000", item.evidence)

    def test_owasp_baseline_is_correct(self) -> None:
        item = self.verdict("max-age=63072000; includeSubDomains")
        self.assertEqual(item.status, "correcta")

    def test_one_year_with_subdomains_is_below_adopted_baseline(self) -> None:
        item = self.verdict("max-age=31536000; includeSubDomains")
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("inferior", item.evidence)

    def test_two_years_without_subdomains_is_incomplete(self) -> None:
        item = self.verdict("max-age=63072000")
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("falta includeSubDomains", item.evidence)

    def test_unknown_extension_is_ignored_per_rfc6797(self) -> None:
        item = self.verdict(
            "max-age=63072000; includeSubDomains; future-extension=value"
        )
        self.assertEqual(item.status, "correcta")
        self.assertIn("debe ignorar", item.evidence)

    def test_unknown_quoted_extension_may_contain_semicolon(self) -> None:
        item = self.verdict(
            'max-age=63072000; includeSubDomains; future-extension="a;b"'
        )
        self.assertEqual(item.status, "correcta")

    def test_malformed_quoted_value_invalidates_hsts(self) -> None:
        item = self.verdict('max-age="63072000; includeSubDomains')
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("sin cierre", item.evidence)

    def test_text_after_quoted_value_invalidates_hsts(self) -> None:
        item = self.verdict('max-age="63072000"extra; includeSubDomains')
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("texto adicional", item.evidence)

    def test_invalid_unknown_directive_name_invalidates_field(self) -> None:
        item = self.verdict("max-age=63072000; includeSubDomains; bad name=value")
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("nombre de directiva", item.evidence)

    def test_quoted_pair_is_unescaped_before_max_age_validation(self) -> None:
        item = self.verdict('max-age="63072\\000"; includeSubDomains')
        self.assertEqual(item.status, "correcta")

    def test_extremely_large_max_age_does_not_crash_integer_conversion(self) -> None:
        item = self.verdict("max-age=" + "9" * 10_000 + "; includeSubDomains")
        self.assertEqual(item.status, "correcta")
        self.assertIn("extremadamente grande", item.evidence)

    def test_quoted_max_age_is_accepted(self) -> None:
        item = self.verdict('max-age="63072000"; includeSubDomains')
        self.assertEqual(item.status, "correcta")

    def test_max_age_zero_is_incorrect_once(self) -> None:
        item = self.verdict("max-age=0; includeSubDomains")
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("deshabilitado", item.title)

    def test_preload_without_subdomains_is_incorrect_once(self) -> None:
        item = self.verdict("max-age=63072000; preload")
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("preload", item.evidence)

    def test_duplicate_directive_is_invalid_once(self) -> None:
        item = self.verdict("max-age=63072000; max-age=31536000; includeSubDomains")
        self.assertEqual(item.status, "incorrecta")
        self.assertIn("duplicadas", item.evidence)

    def test_multiple_header_fields_are_one_incorrect_result(self) -> None:
        snap = snapshot(
            Strict_Transport_Security=[
                "max-age=63072000; includeSubDomains",
                "max-age=0",
            ]
        )
        findings = swh.analyze_hsts(snap, set())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "incorrecta")
        self.assertIn("primer campo", findings[0].risk)


class AntiFramingVerdictTests(unittest.TestCase):
    def xfo_verdict(self, snap: swh.ResponseSnapshot) -> swh.Finding:
        findings = swh.analyze_x_frame_options(snap, set(), "web")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].header, "X-Frame-Options")
        return findings[0]

    def test_missing_xfo_is_reported_by_its_real_header_name(self) -> None:
        self.assertEqual(self.xfo_verdict(snapshot()).status, "ausente")

    def test_xfo_deny_alone_is_correct(self) -> None:
        item = self.xfo_verdict(snapshot(X_Frame_Options="DENY"))
        self.assertEqual(item.status, "correcta")
        self.assertNotEqual(item.category, "obsoletas")

    def test_xfo_sameorigin_alone_is_correct(self) -> None:
        self.assertEqual(
            self.xfo_verdict(snapshot(X_Frame_Options="SAMEORIGIN")).status,
            "correcta",
        )

    def test_allow_from_is_one_obsolete_xfo_result(self) -> None:
        item = self.xfo_verdict(snapshot(X_Frame_Options="ALLOW-FROM https://a.test"))
        self.assertEqual(item.category, "obsoletas")
        self.assertIn("ALLOW-FROM", item.title)

    def test_multiple_xfo_fields_are_incorrect_once(self) -> None:
        item = self.xfo_verdict(snapshot(X_Frame_Options=["DENY", "SAMEORIGIN"]))
        self.assertEqual(item.status, "incorrecta")

    def test_xfo_exclusion_creates_only_hidden_exclusion_marker(self) -> None:
        findings = swh.analyze_x_frame_options(
            snapshot(X_Frame_Options="DENY"), {"x-frame-options"}, "web"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "excluida")

    def test_csp_missing_frame_remains_a_csp_issue_when_xfo_is_valid(self) -> None:
        raw = (
            "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'"
        )
        snap = snapshot(X_Frame_Options="SAMEORIGIN", Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        frame = [item for item in findings if "frame-ancestors" in item.title]
        self.assertTrue(frame)
        self.assertTrue(all(item.status == "ausente" for item in frame))
        self.assertTrue(all(item.header == "Content-Security-Policy" for item in frame))

    def test_csp_frame_ancestors_is_evaluated_inside_csp(self) -> None:
        raw = (
            "default-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        findings = swh.analyze_csp_headers(
            snapshot(Content_Security_Policy=raw), set(), "web"
        )
        frame = [item for item in findings if "frame-ancestors" in item.title]
        self.assertTrue(frame)
        self.assertTrue(all(item.header == "Content-Security-Policy" for item in frame))
        self.assertTrue(any(item.status == "correcta" for item in frame))

    def test_csp_wildcard_does_not_change_xfo_verdict(self) -> None:
        snap = snapshot(
            X_Frame_Options="DENY",
            Content_Security_Policy="frame-ancestors *",
        )
        self.assertEqual(self.xfo_verdict(snap).status, "correcta")
        csp = swh.analyze_csp_headers(snap, set(), "web")
        self.assertTrue(
            any(
                item.header == "Content-Security-Policy"
                and "frame-ancestors" in item.title
                and item.status == "incorrecta"
                for item in csp
            )
        )

    def test_no_synthetic_header_name_is_emitted(self) -> None:
        snap = snapshot(
            X_Frame_Options="DENY",
            Content_Security_Policy="frame-ancestors 'none'",
        )
        findings = [
            *swh.analyze_x_frame_options(snap, set(), "web"),
            *swh.analyze_csp_headers(snap, set(), "web"),
        ]
        self.assertNotIn("Protección anti-framing", {item.header for item in findings})


class CorsVerdictTests(unittest.TestCase):
    def test_reflection_with_credentials_has_one_acao_verdict(self) -> None:
        origin = "http://127.0.0.1:8000"
        probe = snapshot(
            Access_Control_Allow_Origin=origin,
            Access_Control_Allow_Credentials="true",
            Vary="Origin",
        )
        findings = swh.analyze_cors(snapshot(), set(), probe, origin)
        acao = [
            item for item in findings if item.header == "Access-Control-Allow-Origin"
        ]
        self.assertEqual(len(acao), 1)
        self.assertEqual(acao[0].status, "incorrecta")

    def test_reflection_without_credentials_is_still_arbitrary_read(self) -> None:
        origin = "http://127.0.0.1:8000"
        probe = snapshot(Access_Control_Allow_Origin=origin, Vary="Origin")
        item = swh.analyze_cors(snapshot(), set(), probe, origin)[0]
        self.assertEqual(item.status, "incorrecta")

    def test_wildcard_with_credentials_is_not_claimed_as_bypass(self) -> None:
        findings = swh.analyze_cors(
            snapshot(
                Access_Control_Allow_Origin="*",
                Access_Control_Allow_Credentials="true",
            ),
            set(),
        )
        self.assertEqual(findings[0].status, "incorrecta")
        self.assertIn("bloquean", findings[0].risk)

    def test_wildcard_without_credentials_is_contextual(self) -> None:
        findings = swh.analyze_cors(snapshot(Access_Control_Allow_Origin="*"), set())
        self.assertEqual(findings[0].status, "informativa")

    def test_uppercase_true_is_invalid_per_mdn(self) -> None:
        findings = swh.analyze_cors(
            snapshot(
                Access_Control_Allow_Origin="https://trusted.example",
                Access_Control_Allow_Credentials="TRUE",
            ),
            set(),
        )
        credentials = [
            item
            for item in findings
            if item.header == "Access-Control-Allow-Credentials"
        ]
        self.assertEqual(len(credentials), 1)
        self.assertEqual(credentials[0].status, "incorrecta")

    def test_probe_not_allowed_is_one_correct_acao_verdict(self) -> None:
        origin = "http://127.0.0.1:8000"
        probe = snapshot(Access_Control_Allow_Origin="https://trusted.example")
        findings = swh.analyze_cors(snapshot(), set(), probe, origin)
        acao = [
            item for item in findings if item.header == "Access-Control-Allow-Origin"
        ]
        self.assertEqual(len(acao), 1)
        self.assertEqual(acao[0].status, "correcta")


class CookieAndDateOutputTests(unittest.TestCase):
    def test_cookie_findings_have_their_own_category(self) -> None:
        snap = snapshot(Set_Cookie="session=secret; Secure; SameSite=Lax")
        report = report_from_snapshot(snap, swh.analyze_cookies(snap, set()))
        groups = swh.build_display_groups(report)
        self.assertEqual(len(groups["cookies"]), 1)
        self.assertFalse(groups["incorrectas"])

    def test_cookie_current_value_does_not_mix_other_cookies(self) -> None:
        snap = snapshot(
            Set_Cookie=[
                "session=secret; Secure; HttpOnly; SameSite=Lax",
                "theme=dark; Secure; SameSite=Lax",
            ]
        )
        report = report_from_snapshot(snap, swh.analyze_cookies(snap, set()))
        entries = swh.build_display_groups(report)["cookies"]
        self.assertEqual(len(entries), 2)
        self.assertIn("Cookie session", entries[0].current_value)
        self.assertNotIn("Cookie theme", entries[0].current_value)

    def test_cookie_summary_counts_each_cookie(self) -> None:
        snap = snapshot(
            Set_Cookie=[
                "session=secret; Secure; HttpOnly; SameSite=Lax",
                "theme=dark; Secure; SameSite=Lax",
            ]
        )
        report = report_from_snapshot(snap, swh.analyze_cookies(snap, set()))
        self.assertEqual(swh.summarize_report(report)["cookies"], 2)

    def test_console_hides_numeric_timezone_offset(self) -> None:
        snap = snapshot()
        report = report_from_snapshot(snap)
        rendered = swh.render_console(report, color=False, reveal_sensitive=False)
        self.assertIn("Fecha y hora", rendered)
        self.assertNotIn("-0500", rendered)
        self.assertNotIn("-05:00", rendered)
        self.assertIn("2026-08-11 18:04:22", rendered)

    def test_machine_timestamp_is_preserved_in_json(self) -> None:
        report = report_from_snapshot(snapshot())
        self.assertEqual(report.to_dict()["timestamp"], "2026-08-11T18:04:22-05:00")

    def test_html_omits_cookie_metric_when_cookie_analysis_has_no_findings(
        self,
    ) -> None:
        rendered = swh.render_html(report_from_snapshot(snapshot()), False)
        self.assertNotIn("<span>Cookies</span>", rendered)

    def test_html_shows_cookie_metric_when_cookie_findings_exist(self) -> None:
        snap = snapshot(Set_Cookie="session=secret; Secure; HttpOnly; SameSite=Lax")
        report = report_from_snapshot(snap, swh.analyze_cookies(snap, set()))
        rendered = swh.render_html(report, False)
        self.assertIn("<span>Cookies</span><strong>1</strong>", rendered)

    def test_display_timestamp_supports_both_offset_formats(self) -> None:
        self.assertEqual(
            swh.display_timestamp("2026-08-11 18:04:22 -0500"),
            "2026-08-11 18:04:22",
        )
        self.assertEqual(
            swh.display_timestamp("2026-08-11T18:04:22-05:00"),
            "2026-08-11 18:04:22",
        )


class PocGenerationTests(unittest.TestCase):
    def test_frame_poc_contains_iframe_and_observed_controls(self) -> None:
        snap = snapshot(
            X_Frame_Options="SAMEORIGIN",
            Content_Security_Policy="frame-ancestors 'self'",
        )
        report = report_from_snapshot(snap)
        with tempfile.TemporaryDirectory() as directory:
            path = swh.generate_frame_poc(report, Path(directory))
            content = path.read_text(encoding="utf-8")
        self.assertIn("<iframe", content)
        self.assertIn("SAMEORIGIN", content)
        self.assertIn("frame-ancestors", content)
        self.assertIn(snap.url, content)

    def test_cors_poc_uses_exact_origin_and_two_credential_modes(self) -> None:
        report = report_from_snapshot(snapshot())
        origin = "http://127.0.0.1:8765"
        with tempfile.TemporaryDirectory() as directory:
            path = swh.generate_cors_poc(report, Path(directory), origin)
            content = path.read_text(encoding="utf-8")
        self.assertIn(origin, content)
        self.assertIn('run("omit")', content)
        self.assertIn('run("include")', content)
        self.assertIn("no exfiltra", content)
        self.assertNotIn("innerHTML", content)

    def test_csp_poc_states_that_policy_weakness_is_not_xss(self) -> None:
        raw = "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'"
        snap = snapshot(Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        report = report_from_snapshot(snap, findings)
        with tempfile.TemporaryDirectory() as directory:
            path = swh.generate_csp_poc(report, Path(directory))
            content = path.read_text(encoding="utf-8")
        self.assertIn("no demuestra XSS", content)
        self.assertIn("unsafe-inline", content)
        self.assertIn("punto de inyección", content)

    def test_poc_names_do_not_overwrite_existing_files(self) -> None:
        report = report_from_snapshot(snapshot(X_Frame_Options="DENY"))
        with tempfile.TemporaryDirectory() as directory:
            first = swh.generate_frame_poc(report, Path(directory))
            second = swh.generate_frame_poc(report, Path(directory))
        self.assertNotEqual(first.name, second.name)

    def test_offline_cli_generates_csp_poc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = swh.main(
                    [
                        "--csp-policy",
                        "default-src 'self'; script-src 'unsafe-inline'",
                        "--poc-csp",
                        "--poc-dir",
                        directory,
                    ]
                )
            files = list(Path(directory).glob("poc-csp-*.html"))
        self.assertEqual(code, 0)
        self.assertEqual(len(files), 1)


class _LocalHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.path == "/cors":
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")
        if self.path == "/cookie":
            self.send_header(
                "Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Lax"
            )
        if self.path == "/frame":
            self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def log_message(self, format: str, *args: object) -> None:
        return


class LocalHttpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_real_cors_probe_reflection_is_detected_once(self) -> None:
        args = swh.build_parser().parse_args([self.base + "/cors", "--test-cors"])
        report = swh.create_report(args)
        acao = [
            item
            for item in report.findings
            if item.header == "Access-Control-Allow-Origin"
        ]
        self.assertEqual(len(acao), 1)
        self.assertEqual(acao[0].status, "incorrecta")

    def test_real_plural_exclusion_suppresses_referrer_check(self) -> None:
        args = swh.build_parser().parse_args(
            [self.base + "/final", "--exclude-headers", "Referrer-Policy"]
        )
        report = swh.create_report(args)
        visible = [
            item
            for item in report.findings
            if item.header == "Referrer-Policy" and item.status != "excluida"
        ]
        self.assertEqual(visible, [])
        self.assertIn("Referrer-Policy", report.excluded_headers)

    def test_real_cookie_analysis_uses_separate_category(self) -> None:
        args = swh.build_parser().parse_args([self.base + "/cookie", "--value-cookie"])
        report = swh.create_report(args)
        groups = swh.build_display_groups(report)
        self.assertEqual(len(groups["cookies"]), 1)

    def test_real_cookie_analysis_is_absent_without_value_cookie(self) -> None:
        args = swh.build_parser().parse_args([self.base + "/cookie"])
        report = swh.create_report(args)
        self.assertEqual(swh.build_display_groups(report)["cookies"], [])

    def test_real_frame_header_has_one_correct_xfo_result(self) -> None:
        args = swh.build_parser().parse_args([self.base + "/frame"])
        report = swh.create_report(args)
        framing = [item for item in report.findings if item.header == "X-Frame-Options"]
        self.assertEqual(len(framing), 1)
        self.assertEqual(framing[0].status, "correcta")

    def test_real_redirect_chain_is_followed_when_requested(self) -> None:
        args = swh.build_parser().parse_args(
            [self.base + "/redirect", "--follow-redirects"]
        )
        report = swh.create_report(args)
        self.assertEqual(len(report.redirects), 2)
        self.assertTrue(report.final_url.endswith("/final"))


if __name__ == "__main__":
    unittest.main()
