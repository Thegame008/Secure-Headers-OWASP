from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "safewebheaders.py"
SPEC = importlib.util.spec_from_file_location("safewebheaders_v7", SCRIPT)
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
        elapsed_ms=3,
    )


def report_from_snapshot(
    snap: swh.ResponseSnapshot, findings: list[swh.Finding] | None = None
) -> swh.ScanReport:
    return swh.ScanReport(
        tool="SafeWebHeaders",
        version=swh.VERSION,
        timestamp="2026-08-12T10:15:30-05:00",
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
        resolved_ips=["192.0.2.10", "2001:db8::10"],
    )


class RealHeaderNameTests(unittest.TestCase):
    def test_xfo_missing_keeps_real_name_even_when_csp_is_present(self) -> None:
        snap = snapshot(Content_Security_Policy="frame-ancestors 'none'")
        item = swh.analyze_x_frame_options(snap, set(), "web")[0]
        self.assertEqual(item.header, "X-Frame-Options")
        self.assertEqual(item.status, "ausente")

    def test_xfo_deny_is_case_insensitive(self) -> None:
        item = swh.analyze_x_frame_options(
            snapshot(X_Frame_Options="  deny  "), set(), "web"
        )[0]
        self.assertEqual(item.status, "correcta")

    def test_xfo_unknown_value_is_incorrect(self) -> None:
        item = swh.analyze_x_frame_options(
            snapshot(X_Frame_Options="ALLOWALL"), set(), "web"
        )[0]
        self.assertEqual(item.status, "incorrecta")
        self.assertEqual(item.header, "X-Frame-Options")

    def test_valid_content_type_is_visible_as_a_checked_real_header(self) -> None:
        item = swh.analyze_content_type(
            snapshot(Content_Type="text/html; charset=UTF-8"), set()
        )[0]
        self.assertEqual(item.header, "Content-Type")
        self.assertEqual(item.status, "correcta")

    def test_xfo_allow_from_is_obsolete_once(self) -> None:
        findings = swh.analyze_x_frame_options(
            snapshot(X_Frame_Options="ALLOW-FROM https://portal.test"), set(), "web"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "obsoletas")

    def test_api_without_xfo_does_not_create_html_only_noise(self) -> None:
        self.assertEqual(swh.analyze_x_frame_options(snapshot(), set(), "api"), [])

    def test_api_with_xfo_is_still_validated(self) -> None:
        item = swh.analyze_x_frame_options(
            snapshot(X_Frame_Options="invalid"), set(), "api"
        )[0]
        self.assertEqual(item.status, "incorrecta")

    def test_full_analysis_never_emits_synthetic_header_name(self) -> None:
        snap = snapshot(
            Strict_Transport_Security="max-age=63072000; includeSubDomains",
            X_Content_Type_Options="nosniff",
            Referrer_Policy="strict-origin-when-cross-origin",
            X_Frame_Options="DENY",
            Content_Security_Policy=(
                "default-src 'self'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'"
            ),
            Content_Type="text/html; charset=UTF-8",
        )
        findings = swh.run_analysis(
            snap,
            snapshots=[snap],
            excluded=set(),
            profile="web",
            follow_redirects=False,
        )
        names = {item.header for item in findings}
        self.assertIn("X-Frame-Options", names)
        self.assertIn("Content-Security-Policy", names)
        self.assertNotIn("Permissions-Policy", names)
        self.assertNotIn("Protección anti-framing", names)

    def test_missing_permissions_policy_is_optional_for_web_documents(self) -> None:
        self.assertEqual(swh.analyze_permissions_policy(snapshot(), set(), "web"), [])

    def test_cross_origin_findings_keep_each_real_header_name(self) -> None:
        findings = swh.analyze_cross_origin_headers(
            snapshot(Cross_Origin_Opener_Policy="same-origin"), set(), "web"
        )
        names = {item.header for item in findings}
        self.assertIn("Cross-Origin-Opener-Policy", names)
        self.assertNotIn("Cross-Origin-Embedder-Policy", names)
        self.assertNotIn("Cross-Origin-Resource-Policy", names)
        self.assertNotIn("Aislamiento cross-origin", names)


class ReferrerPolicyCriterionTests(unittest.TestCase):
    def test_missing_referrer_policy_is_explicitly_contextualized(self) -> None:
        item = swh.analyze_referrer_policy(snapshot(), set(), "web")[0]
        self.assertEqual(item.status, "ausente")
        self.assertIn("no es una obligación", item.title)
        self.assertIn("predeterminado", item.evidence)

    def test_referrer_policy_criterion_explains_owasp_and_browser_default(self) -> None:
        item = swh.analyze_referrer_policy(snapshot(), set(), "web")[0]
        criterion = swh.finding_criterion(item)
        self.assertIn("OWASP", criterion)
        self.assertIn("MDN", criterion)
        self.assertIn("navegadores modernos", criterion)

    def test_unsafe_url_is_incorrect(self) -> None:
        item = swh.analyze_referrer_policy(
            snapshot(Referrer_Policy="unsafe-url"), set(), "web"
        )[0]
        self.assertEqual(item.status, "incorrecta")

    def test_strict_origin_when_cross_origin_is_correct(self) -> None:
        item = swh.analyze_referrer_policy(
            snapshot(Referrer_Policy="strict-origin-when-cross-origin"),
            set(),
            "web",
        )[0]
        self.assertEqual(item.status, "correcta")


class IpOutputTests(unittest.TestCase):
    def test_literal_ipv4_resolution_is_stable(self) -> None:
        self.assertEqual(swh.resolve_url_ips("https://192.0.2.44/"), ["192.0.2.44"])

    def test_literal_ipv6_resolution_is_stable(self) -> None:
        self.assertEqual(
            swh.resolve_url_ips("https://[2001:db8::44]/"), ["2001:db8::44"]
        )

    def test_ip_is_printed_immediately_after_date_in_each_category(self) -> None:
        snap = snapshot(X_Frame_Options="DENY")
        report = report_from_snapshot(
            snap, swh.analyze_x_frame_options(snap, set(), "web")
        )
        rendered = swh.render_console(report, color=False, reveal_sensitive=False)
        self.assertIn(
            "Date: 2026-08-12 10:15:30\nIP(s): 192.0.2.10, 2001:db8::10\n",
            rendered,
        )

    def test_json_and_csv_include_resolved_ips(self) -> None:
        snap = snapshot(X_Frame_Options="DENY")
        report = report_from_snapshot(
            snap, swh.analyze_x_frame_options(snap, set(), "web")
        )
        self.assertEqual(report.to_dict()["resolved_ips"], report.resolved_ips)
        batch = swh.BatchReport(
            tool="SafeWebHeaders",
            version=swh.VERSION,
            timestamp=report.timestamp,
            requested_targets=[report.requested_url],
            reports=[report],
            errors=[],
        )
        rows = list(csv.DictReader(io.StringIO(swh.render_batch_csv(batch, False))))
        self.assertTrue(any("192.0.2.10" in row["ips_resueltas"] for row in rows))


class ExportBehaviorTests(unittest.TestCase):
    def make_batch(self) -> swh.BatchReport:
        snap = snapshot(X_Frame_Options="DENY")
        report = report_from_snapshot(
            snap, swh.analyze_x_frame_options(snap, set(), "web")
        )
        return swh.BatchReport(
            tool="SafeWebHeaders",
            version=swh.VERSION,
            timestamp=report.timestamp,
            requested_targets=[report.requested_url],
            reports=[report],
            errors=[],
        )

    def test_output_prints_normal_console_and_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            args = swh.build_parser().parse_args(
                ["https://example.test", "--output", str(output), "--no-color"]
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                swh.write_batch_output(self.make_batch(), args)
            saved = json.loads(output.read_text(encoding="utf-8"))
        self.assertIn("SafeWebHeaders", stdout.getvalue())
        self.assertIn("Reporte JSON guardado", stdout.getvalue())
        self.assertIn("summary_general", saved)

    def test_quiet_writes_file_without_full_console(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.txt"
            args = swh.build_parser().parse_args(
                ["https://example.test", "-o", str(output), "--quiet"]
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                swh.write_batch_output(self.make_batch(), args)
            saved = output.read_text(encoding="utf-8")
        self.assertNotIn("Resumen por URL", stdout.getvalue())
        self.assertIn("Resumen por URL", saved)

    def test_export_alias_and_explicit_format_are_accepted(self) -> None:
        args = swh.build_parser().parse_args(
            [
                "https://example.test",
                "--export",
                "report",
                "--export-format",
                "csv",
            ]
        )
        self.assertEqual(args.output, "report")
        self.assertEqual(swh.determine_output_format(args), "csv")

    def test_quiet_without_output_is_rejected(self) -> None:
        args = swh.build_parser().parse_args(["https://example.test", "--quiet"])
        with self.assertRaisesRegex(swh.ScanError, "requiere"):
            swh.validate_args(args)


class PocClarityTests(unittest.TestCase):
    def test_basic_frame_poc_has_no_fake_login(self) -> None:
        report = report_from_snapshot(snapshot(X_Frame_Options="DENY"))
        with tempfile.TemporaryDirectory() as directory:
            path = swh.generate_frame_poc(report, Path(directory))
            content = path.read_text(encoding="utf-8")
        self.assertNotIn("demo-user", content)
        self.assertIn("PoC básica", content)

    def test_overlay_poc_captures_only_locally(self) -> None:
        report = report_from_snapshot(snapshot())
        with tempfile.TemporaryDirectory() as directory:
            path = swh.generate_frame_poc(report, Path(directory), interactive=True)
            content = path.read_text(encoding="utf-8")
        self.assertIn("Usuario ficticio", content)
        self.assertIn("CAPTURA LOCAL DE DEMOSTRACIÓN", content)
        self.assertIn("CAPTURA LOCAL DE DEMOSTRACIÓN\\nUsuario", content)
        self.assertIn("No se envió información", content)
        self.assertNotIn("fetch(", content)
        self.assertNotIn("XMLHttpRequest", content)

    def test_overlay_flag_is_independent_from_basic_frame_flag(self) -> None:
        args = swh.build_parser().parse_args(
            ["https://example.test", "--poc-frame-overlay"]
        )
        self.assertTrue(args.poc_frame_overlay)
        self.assertFalse(args.poc_frame)

    def test_cors_poc_shows_probe_headers_and_interpretation(self) -> None:
        origin = "http://127.0.0.1:8765"
        report = report_from_snapshot(snapshot())
        report.cors_probe_origin = origin
        report.cors_probe_status_code = 200
        report.cors_probe_headers = {
            "access-control-allow-origin": [origin],
            "access-control-allow-credentials": ["true"],
            "vary": ["Origin"],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = swh.generate_cors_poc(report, Path(directory), origin)
            content = path.read_text(encoding="utf-8")
        self.assertIn("Resultado de la sonda", content)
        self.assertIn("Access-Control-Allow-Origin", content)
        self.assertIn("LECTURA AUTENTICADA PERMITIDA", content)
        self.assertIn("LECTURA PERMITIDA POR EL NAVEGADOR\\n", content)
        self.assertIn("no equivale", content.lower())

    def test_help_uses_final_script_name_and_explains_export_behavior(self) -> None:
        help_text = swh.build_parser().format_help()
        self.assertIn("python safewebheaders.py", help_text)
        self.assertNotIn("python mejora.py", help_text)
        self.assertIn("PANTALLA + ARCHIVO", help_text)
        self.assertIn("ALCANCE PREDETERMINADO Y NOMBRES REALES", help_text)
        self.assertIn("--poc-frame-overlay", help_text)


if __name__ == "__main__":
    unittest.main()
