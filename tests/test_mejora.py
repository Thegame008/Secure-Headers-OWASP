from __future__ import annotations

import argparse
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
if not SCRIPT.exists():
    SCRIPT = ROOT / "upload" / "mejora.py"
# Un nombre propio evita sustituir el paquete real en ``sys.modules`` y
# romper cualquier test posterior que importe ``safewebheaders.<submódulo>``.
SPEC = importlib.util.spec_from_file_location("safewebheaders_flat", SCRIPT)
assert SPEC and SPEC.loader
swh = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = swh
SPEC.loader.exec_module(swh)


def snapshot(
    url: str = "https://example.test/", **headers: str
) -> swh.ResponseSnapshot:
    normalized = {
        swh.normalize_header_name(name): [value] for name, value in headers.items()
    }
    names = {key: swh.canonical_header(key) for key in normalized}
    return swh.ResponseSnapshot(
        url=url,
        status_code=200,
        reason="OK",
        headers=normalized,
        display_names=names,
        elapsed_ms=10,
    )


class ParsingTests(unittest.TestCase):
    def test_url_without_scheme_defaults_to_https(self) -> None:
        self.assertEqual(swh.normalize_url("example.com/a"), "https://example.com/a")

    def test_url_fragment_is_removed_before_the_http_request(self) -> None:
        self.assertEqual(
            swh.normalize_url("https://example.com/a?x=1#access_token=secret"),
            "https://example.com/a?x=1",
        )

    def test_embedded_credentials_are_rejected(self) -> None:
        with self.assertRaises(swh.ScanError):
            swh.normalize_url("https://user:secret@example.com/")

    def test_invalid_target_port_raises_clean_scan_error(self) -> None:
        with self.assertRaisesRegex(swh.ScanError, "host o puerto inválido"):
            swh.normalize_url("https://example.test:not-a-port")

    def test_header_aliases_and_commas_are_normalized(self) -> None:
        excluded = swh.parse_exclusions(["CSP, HSTS", "Server"])
        self.assertEqual(
            excluded,
            {
                "content-security-policy",
                "strict-transport-security",
                "server",
            },
        )

    def test_unknown_exclusion_is_rejected_with_suggestion(self) -> None:
        with self.assertRaisesRegex(swh.ScanError, "strict-transport-security"):
            swh.parse_exclusions(["strict-transprot-security"])

    def test_exclusion_groups_are_supported(self) -> None:
        excluded = swh.parse_exclusions(["obsoletas", "divulgacion"])
        self.assertTrue(swh.LEGACY_HEADER_NAMES <= excluded)
        self.assertTrue(swh.DISCLOSURE_HEADER_NAMES <= excluded)

    def test_collect_targets_combines_arguments_and_file_without_duplicates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_file = Path(directory) / "urls.txt"
            target_file.write_text(
                "# comentario\nhttps://dos.test\n\nhttps://tres.test\n",
                encoding="utf-8",
            )
            args = argparse.Namespace(
                urls=["https://uno.test", "https://dos.test"],
                url_file=[str(target_file)],
            )
            self.assertEqual(
                swh.collect_targets(args),
                [
                    "https://uno.test",
                    "https://dos.test",
                    "https://tres.test",
                ],
            )

    def test_help_explains_exclusion_and_batch_syntax(self) -> None:
        help_text = swh.build_parser().format_help()
        self.assertIn("--exclude-header Strict-Transport-Security", help_text)
        self.assertIn("--exclude-header X-Frame-Options", help_text)
        self.assertIn("Varias URL separadas por espacios", help_text)
        self.assertIn("--url-file urls.txt", help_text)
        self.assertIn("--output reporte.csv", help_text)

    def test_csp_duplicate_keeps_first_directive(self) -> None:
        policy = swh.parse_csp("default-src 'self'; default-src *; object-src 'none'")
        self.assertEqual(policy.values("default-src"), ["'self'"])
        self.assertEqual(policy.duplicates, ["default-src"])

    def test_base64_nonce_decodes_without_destroying_case(self) -> None:
        policy = swh.parse_csp("script-src 'nonce-MDEyMzQ1Njc4OWFiY2RlZg=='")
        nonces = swh.csp_nonces(policy.values("script-src"))
        self.assertEqual(nonces[0][0], "MDEyMzQ1Njc4OWFiY2RlZg==")
        self.assertEqual(len(nonces[0][1]), 16)


class HeaderRuleTests(unittest.TestCase):
    def test_hsts_parses_directives_in_any_case_and_order(self) -> None:
        snap = snapshot(Strict_Transport_Security="includeSubDomains; MAX-AGE=63072000")
        findings = swh.analyze_hsts(snap, set())
        self.assertTrue(any(item.status == "correcta" for item in findings))
        self.assertFalse(any(item.status == "incorrecta" for item in findings))

    def test_hsts_over_http_redirect_is_not_treated_as_valid(self) -> None:
        snap = snapshot(
            "http://example.test/",
            Strict_Transport_Security="max-age=63072000",
        )
        findings = swh.analyze_hsts(snap, set())
        self.assertTrue(any(item.severity == "alta" for item in findings))

    def test_hsts_on_http_to_https_redirect_requests_follow_up(self) -> None:
        snap = snapshot("http://example.test/", Location="https://example.test/")
        snap.status_code = 301
        findings = swh.analyze_hsts(snap, set())
        self.assertTrue(
            any("--follow-redirects" in item.recommendation for item in findings)
        )
        self.assertFalse(any(item.severity == "alta" for item in findings))

    def test_hsts_duplicate_directive_is_rejected(self) -> None:
        snap = snapshot(Strict_Transport_Security="max-age=0; max-age=63072000")
        findings = swh.analyze_hsts(snap, set())
        self.assertTrue(any("duplicadas" in item.evidence for item in findings))

    def test_hsts_is_contextual_for_ip_addresses(self) -> None:
        snap = snapshot(
            "https://127.0.0.1/",
            Strict_Transport_Security="max-age=63072000",
        )
        findings = swh.analyze_hsts(snap, set())
        self.assertTrue(any("direcciones IP" in item.title for item in findings))
        self.assertFalse(any(item.severity == "alta" for item in findings))

    def test_x_xss_protection_legacy_value_is_flagged(self) -> None:
        snap = snapshot(X_XSS_Protection="1; mode=block")
        findings = swh.analyze_legacy_and_deprecated(snap, set())
        self.assertTrue(
            any(
                item.header == "X-XSS-Protection" and item.status == "incorrecta"
                for item in findings
            )
        )

    def test_x_frame_options_keeps_its_real_header_name(self) -> None:
        snap = snapshot(
            X_Frame_Options="SAMEORIGIN",
            Content_Security_Policy="frame-ancestors 'self'",
        )
        findings = swh.analyze_x_frame_options(snap, set(), "web")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].header, "X-Frame-Options")
        self.assertEqual(findings[0].status, "correcta")
        self.assertNotEqual(findings[0].category, "obsoletas")

    def test_cookie_value_is_redacted(self) -> None:
        redacted = swh.redact_set_cookie("session=supersecret; Secure; HttpOnly")
        self.assertNotIn("supersecret", redacted)
        self.assertIn("session=<redactado>", redacted)

    def test_cookie_prefix_requirements_are_checked(self) -> None:
        snap = snapshot(Set_Cookie="__Host-session=secret; Path=/; HttpOnly")
        findings = swh.analyze_cookies(snap, set())
        self.assertTrue(any("__Host-" in item.evidence for item in findings))
        self.assertTrue(any(item.severity == "media" for item in findings))

    def test_cookie_without_secure_is_reported_even_on_http(self) -> None:
        snap = snapshot("http://example.test/", Set_Cookie="session=secret; HttpOnly")
        findings = swh.analyze_cookies(snap, set())
        evidence = " ".join(item.evidence for item in findings)
        self.assertIn("falta Secure", evidence)
        self.assertIn("emitida desde HTTP", evidence)

    def test_non_session_cookie_does_not_require_httponly_automatically(self) -> None:
        snap = snapshot(Set_Cookie="theme=dark; Secure; SameSite=Lax")
        findings = swh.analyze_cookies(snap, set())
        self.assertTrue(any(item.status == "correcta" for item in findings))

    def test_modern_cookie_prefix_and_partitioned_rules_are_checked(self) -> None:
        snap = snapshot(
            Set_Cookie="__Host-Http-session=secret; Partitioned; Path=/; SameSite=None"
        )
        findings = swh.analyze_cookies(snap, set())
        evidence = " ".join(item.evidence for item in findings)
        self.assertIn("Partitioned sin Secure", evidence)
        self.assertIn("__Host-Http- sin HttpOnly", evidence)

    def test_sensitive_response_requires_no_store(self) -> None:
        snap = snapshot(Cache_Control="private, no-cache")
        findings = swh.analyze_contextual_response_headers(
            snap, set(), sensitive_response=True
        )
        self.assertTrue(any("falta no-store" in item.evidence for item in findings))

    def test_clear_site_data_requires_quoted_tokens(self) -> None:
        snap = snapshot(Clear_Site_Data="cookies, storage")
        findings = swh.analyze_contextual_response_headers(snap, set())
        self.assertTrue(
            any(
                item.header == "Clear-Site-Data" and item.status == "incorrecta"
                for item in findings
            )
        )

    def test_xpcdp_none_is_accepted(self) -> None:
        snap = snapshot(X_Permitted_Cross_Domain_Policies="none")
        findings = swh.analyze_contextual_response_headers(snap, set())
        self.assertTrue(
            any(
                item.header == "X-Permitted-Cross-Domain-Policies"
                and item.status == "correcta"
                for item in findings
            )
        )

    def test_excluded_header_produces_only_exclusion_result(self) -> None:
        snap = snapshot(Content_Security_Policy="default-src *")
        findings = swh.analyze_csp_headers(snap, {"content-security-policy"}, "web")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "excluida")

    def test_cookie_analysis_is_opt_in(self) -> None:
        snap = snapshot(Set_Cookie="session=secret; Path=/")
        base = {
            "snapshots": [snap],
            "excluded": set(),
            "profile": "web",
            "follow_redirects": False,
        }
        default_findings = swh.run_analysis(snap, **base)
        cookie_findings = swh.run_analysis(snap, **base, evaluate_cookies=True)
        self.assertFalse(any(item.category == "cookies" for item in default_findings))
        self.assertTrue(any(item.category == "cookies" for item in cookie_findings))

    def test_absent_contextual_headers_are_not_emitted(self) -> None:
        snap = snapshot()
        findings = swh.run_analysis(
            snap,
            snapshots=[snap],
            excluded=set(),
            profile="web",
            follow_redirects=False,
        )
        headers = {item.header for item in findings}
        self.assertTrue(
            {
                "Cache-Control",
                "Clear-Site-Data",
                "Cross-Origin-Opener-Policy",
                "Cross-Origin-Embedder-Policy",
                "Cross-Origin-Resource-Policy",
                "X-DNS-Prefetch-Control",
                "X-Permitted-Cross-Domain-Policies",
            }.isdisjoint(headers)
        )
        self.assertNotIn("Permissions-Policy", headers)
        self.assertNotIn("Aislamiento cross-origin", headers)
        self.assertNotIn("Integrity-Policy", headers)


class CSPTests(unittest.TestCase):
    STRICT = (
        "default-src 'self'; "
        "script-src 'nonce-MDEyMzQ1Njc4OWFiY2RlZg==' 'strict-dynamic'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'"
    )

    def test_strict_csp_has_no_high_negative_finding(self) -> None:
        snap = snapshot(Content_Security_Policy=self.STRICT)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        high_negative = [
            item
            for item in findings
            if item.severity == "alta"
            and item.status in {"ausente", "incorrecta", "advertencia"}
        ]
        self.assertEqual(high_negative, [])

    def test_unsafe_inline_and_eval_are_reported(self) -> None:
        raw = "default-src * 'unsafe-inline' 'unsafe-eval'"
        snap = snapshot(Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        titles = " ".join(item.title for item in findings)
        self.assertIn("unsafe-inline", titles)
        self.assertIn("unsafe-eval", titles)
        self.assertTrue(any(item.severity == "alta" for item in findings))

    def test_report_only_is_not_presented_as_enforcement(self) -> None:
        snap = snapshot(Content_Security_Policy_Report_Only=self.STRICT)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        self.assertTrue(
            any(
                item.header == "Content-Security-Policy" and item.category == "ausentes"
                for item in findings
            )
        )

    def test_reused_nonce_is_detected_without_printing_its_value(self) -> None:
        snap = snapshot(Content_Security_Policy=self.STRICT)
        nonce = "MDEyMzQ1Njc4OWFiY2RlZg=="
        findings = swh.analyze_csp_headers(snap, set(), "web", reused_nonces={nonce})
        matches = [item for item in findings if "repitió" in item.title]
        self.assertEqual(len(matches), 1)
        self.assertNotIn(nonce, matches[0].evidence)

    def test_unquoted_nonce_is_reported_as_invalid(self) -> None:
        raw = (
            "default-src 'self'; script-src nonce-MDEyMzQ1Njc4OWFiY2RlZg==; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        snap = snapshot(Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        self.assertTrue(
            any("no está entre comillas" in item.title for item in findings)
        )

    def test_granular_script_directive_is_evaluated(self) -> None:
        raw = (
            "default-src 'self'; script-src 'nonce-MDEyMzQ1Njc4OWFiY2RlZg=='; "
            "script-src-attr 'unsafe-inline'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        snap = snapshot(Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        self.assertTrue(
            any("script-src-attr permite" in item.title for item in findings)
        )

    def test_multiple_policies_do_not_claim_individual_high_is_effective(self) -> None:
        snap = snapshot()
        snap.headers["content-security-policy"] = [
            "default-src * 'unsafe-inline'",
            self.STRICT,
        ]
        findings = swh.analyze_csp_headers(snap, set(), "web")
        policy_specific_high = [
            item
            for item in findings
            if item.policy
            and item.status in {"incorrecta", "ausente"}
            and item.severity == "alta"
        ]
        self.assertEqual(policy_specific_high, [])
        self.assertTrue(any("revisión combinada" in item.title for item in findings))

    def test_empty_source_lists_are_valid_and_block_all(self) -> None:
        raw = (
            "default-src; script-src; object-src; base-uri; "
            "frame-ancestors; form-action"
        )
        policy = swh.parse_csp(raw)
        self.assertEqual(policy.invalid_segments, [])
        snap = snapshot(Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        self.assertTrue(any("lista vacía bloquea" in item.title for item in findings))
        self.assertTrue(
            any(
                item.title == "object-src bloquea objetos embebidos"
                for item in findings
            )
        )

    def test_strict_dynamic_downgrades_legacy_wildcard_fallback(self) -> None:
        raw = self.STRICT.replace(
            "'nonce-MDEyMzQ1Njc4OWFiY2RlZg==' 'strict-dynamic'",
            "'nonce-MDEyMzQ1Njc4OWFiY2RlZg==' 'strict-dynamic' *",
        )
        snap = snapshot(Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        wildcard = [item for item in findings if "comodín global" in item.title]
        self.assertEqual(len(wildcard), 1)
        self.assertEqual(wildcard[0].severity, "baja")

    def test_malformed_quoted_nonce_is_reported_and_redacted(self) -> None:
        raw = self.STRICT.replace(
            "'nonce-MDEyMzQ1Njc4OWFiY2RlZg=='", "'nonce-@@@secret@@@'"
        )
        snap = snapshot(Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        matches = [item for item in findings if "sintaxis no válida" in item.title]
        self.assertEqual(len(matches), 1)
        self.assertNotIn("@@@secret@@@", matches[0].evidence)

    def test_report_only_without_endpoint_is_flagged(self) -> None:
        snap = snapshot(Content_Security_Policy_Report_Only=self.STRICT)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        self.assertTrue(any("destino de reportes" in item.title for item in findings))

    def test_current_csp_directives_are_validated(self) -> None:
        raw = self.STRICT + "; webrtc maybe; require-trusted-types-for script"
        snap = snapshot(Content_Security_Policy=raw)
        findings = swh.analyze_csp_headers(snap, set(), "web")
        titles = " ".join(item.title for item in findings)
        self.assertIn("webrtc tiene un valor inválido", titles)
        self.assertIn("require-trusted-types-for", titles)


class OutputTests(unittest.TestCase):
    def make_report(self) -> swh.ScanReport:
        snap = snapshot(
            Content_Security_Policy=CSPTests.STRICT,
            Set_Cookie="session=supersecret; Secure; HttpOnly; SameSite=Lax",
        )
        findings = swh.analyze_csp_headers(snap, set(), "web")
        return swh.ScanReport(
            tool="SafeWebHeaders",
            version=swh.VERSION,
            timestamp="2026-08-11T12:00:00-05:00",
            requested_url=snap.url,
            final_url=snap.url,
            method="GET",
            status_code=200,
            reason="OK",
            profile="web",
            tls_verification="activa",
            elapsed_ms=10,
            redirect_following=False,
            redirects=[],
            excluded_headers=[],
            findings=findings,
            response_headers=snap.headers,
            display_names=snap.display_names,
            show_headers=True,
        )

    def test_json_hides_set_cookie_by_default(self) -> None:
        report = self.make_report()
        serialized = json.dumps(report.to_dict(False), ensure_ascii=False)
        self.assertNotIn("supersecret", serialized)
        self.assertIn("<redactado>", serialized)

    def test_json_does_not_publish_automatic_severity(self) -> None:
        report = self.make_report()
        serialized = json.dumps(report.to_dict(False), ensure_ascii=False)
        self.assertNotIn('"severity"', serialized)

    def test_json_exposes_redirect_count_separately_from_chain(self) -> None:
        report = self.make_report()
        report.redirects = [swh.RedirectHop("https://example.test/", 200, "", 10)]
        self.assertEqual(report.to_dict(False)["redirect_count"], 0)

    def test_html_contains_url_and_timestamp(self) -> None:
        report = self.make_report()
        rendered = swh.render_html(report, False)
        self.assertIn("https://example.test/", rendered)
        self.assertIn("2026-08-11T12:00:00-05:00", rendered)
        self.assertNotIn("supersecret", rendered)
        self.assertNotIn('class="severity"', rendered)

    def test_console_uses_compact_layout_without_state_or_severity(self) -> None:
        report = self.make_report()
        rendered = swh.render_console(report, color=False, reveal_sensitive=False)
        # 8.5.0: el banner ASCII se sustituyó por el escudo en bloques.
        self.assertTrue(rendered.startswith(" \u2584\u2588"))
        self.assertIn("\u2580\u2580\u2580\u2580", rendered)
        self.assertIn(f"SafeWebHeaders {swh.VERSION}", rendered)
        self.assertIn("URL solicitada", rendered)
        self.assertIn("Resumen por URL", rendered)
        self.assertNotIn("Estado/Severidad", rendered)
        self.assertIn("Perfil", rendered)

    def test_console_orders_categories_and_repeats_date(self) -> None:
        report = self.make_report()
        report.response_headers.update(
            {
                "strict-transport-security": ["max-age=63072000"],
                "x-xss-protection": ["1; mode=block"],
                "server": ["nginx/1.24.0"],
            }
        )
        report.findings = [
            swh.finding(
                "correctas",
                "correcta",
                "informativa",
                "Strict-Transport-Security",
                "HSTS está activo",
            ),
            swh.finding(
                "ausentes",
                "ausente",
                "media",
                "Referrer-Policy",
                "No se encontró la cabecera",
            ),
            swh.finding(
                "incorrectas",
                "incorrecta",
                "media",
                "X-Content-Type-Options",
                "Valor incorrecto",
            ),
            swh.finding(
                "cookies",
                "advertencia",
                "media",
                "Set-Cookie",
                "La cookie session requiere revisión",
                evidence="Cookie session; atributos: Secure; valor ocultado",
            ),
            swh.finding(
                "obsoletas",
                "incorrecta",
                "media",
                "X-XSS-Protection",
                "Cabecera obsoleta habilitada",
            ),
            swh.finding(
                "divulgacion",
                "advertencia",
                "baja",
                "Server",
                "Divulgación tecnológica",
            ),
        ]
        rendered = swh.render_console(report, color=False, reveal_sensitive=False)
        labels = list(swh.DISPLAY_CATEGORY_LABELS.values())[:6]
        positions = [rendered.index(label) for label in labels]
        self.assertEqual(positions, sorted(positions))
        self.assertGreaterEqual(rendered.count("Date: "), 6)
        self.assertIn("Configuración actual en la URL: max-age=63072000", rendered)
        self.assertIn("Configuración actual en la URL: No encontrada", rendered)

    def test_csp_with_issues_is_nested_under_incorrect_category(self) -> None:
        report = self.make_report()
        unsafe = (
            "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'; object-src *"
        )
        report.response_headers["content-security-policy"] = [unsafe]
        report.findings = swh.analyze_csp_headers(
            snapshot(Content_Security_Policy=unsafe), set(), "web"
        )
        rendered = swh.render_console(report, color=False, reveal_sensitive=False)
        incorrect = swh.DISPLAY_CATEGORY_LABELS["incorrectas"]
        self.assertIn(incorrect, rendered)
        self.assertNotIn("Análisis de Content-Security-Policy en la URL", rendered)
        self.assertEqual(rendered.count("[!] Content-Security-Policy\n"), 1)
        self.assertIn("ANÁLISIS DETALLADO DE CSP", rendered)
        self.assertIn("unsafe-eval", rendered)

    def test_console_prints_full_csp_and_highlights_unsafe_tokens(self) -> None:
        report = self.make_report()
        unsafe = (
            "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'; object-src *"
        )
        report.response_headers["content-security-policy"] = [unsafe]
        snap = snapshot(Content_Security_Policy=unsafe)
        report.findings = swh.analyze_csp_headers(snap, set(), "web")
        rendered = swh.render_console(report, color=True, reveal_sensitive=False)
        self.assertIn(unsafe.split(";", 1)[0], rendered)
        self.assertRegex(rendered, r"\x1b\[[0-9;]+m'unsafe-inline'")
        self.assertRegex(rendered, r"\x1b\[[0-9;]+m\*")

    def test_console_does_not_mark_ignored_unsafe_inline_as_effective(self) -> None:
        report = self.make_report()
        fallback = CSPTests.STRICT.replace(
            "'nonce-MDEyMzQ1Njc4OWFiY2RlZg==' 'strict-dynamic'",
            "'nonce-MDEyMzQ1Njc4OWFiY2RlZg==' 'strict-dynamic' 'unsafe-inline'",
        )
        report.response_headers["content-security-policy"] = [fallback]
        snap = snapshot(Content_Security_Policy=fallback)
        report.findings = swh.analyze_csp_headers(snap, set(), "web")
        rendered = swh.render_console(report, color=True, reveal_sensitive=False)
        self.assertIn("'unsafe-inline'", rendered)
        self.assertNotRegex(rendered, r"\x1b\[[0-9;]+m'unsafe-inline'")

    def test_offline_cli_writes_html(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "csp.html"
            exit_code = swh.main(
                ["--csp-policy", CSPTests.STRICT, "--output", str(output)]
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue(output.exists())
            self.assertIn("SafeWebHeaders", output.read_text(encoding="utf-8"))

    def test_batch_json_has_general_and_per_url_summaries(self) -> None:
        first = self.make_report()
        second = self.make_report()
        second.requested_url = "https://second.test/"
        second.final_url = "https://second.test/"
        batch = swh.BatchReport(
            tool="SafeWebHeaders",
            version=swh.VERSION,
            timestamp="2026-08-11 12:00:00 -0500",
            requested_targets=[first.requested_url, second.requested_url],
            reports=[first, second],
            errors=[],
        )
        data = batch.to_dict(False)
        self.assertEqual(data["summary_general"]["urls_solicitadas"], 2)
        self.assertEqual(len(data["results"]), 2)
        self.assertIn("summary", data["results"][0])
        self.assertIn("categories", data["results"][0])

    def test_csv_contains_summary_findings_csp_details_and_errors(self) -> None:
        report = self.make_report()
        unsafe = "default-src *; script-src 'unsafe-inline'"
        report.response_headers["content-security-policy"] = [unsafe]
        report.findings = swh.analyze_csp_headers(
            snapshot(Content_Security_Policy=unsafe), set(), "web"
        )
        batch = swh.BatchReport(
            tool="SafeWebHeaders",
            version=swh.VERSION,
            timestamp=report.timestamp,
            requested_targets=[report.requested_url, "bad://url"],
            reports=[report],
            errors=[swh.ScanFailure("bad://url", report.timestamp, "URL inválida")],
        )
        rows = list(csv.DictReader(io.StringIO(swh.render_batch_csv(batch, False))))
        record_types = {row["tipo_registro"] for row in rows}
        self.assertTrue(
            {"resumen_general", "resumen_url", "hallazgo", "detalle_csp", "error"}
            <= record_types
        )
        self.assertTrue(
            any(row["riesgo"] for row in rows if row["tipo_registro"] == "detalle_csp")
        )


class RedirectAndCorsTests(unittest.TestCase):
    def test_https_to_http_redirect_is_high(self) -> None:
        first = snapshot("https://example.test/start", Location="http://example.test/")
        first.status_code = 302
        second = snapshot("http://example.test/")
        findings = swh.analyze_redirects([first, second], True)
        self.assertTrue(any(item.severity == "alta" for item in findings))

    def test_cors_reflection_with_credentials_is_high(self) -> None:
        base = snapshot()
        origin = "https://random.invalid"
        probe = snapshot(
            Access_Control_Allow_Origin=origin,
            Access_Control_Allow_Credentials="true",
        )
        findings = swh.analyze_cors(base, set(), probe, origin)
        self.assertTrue(any(item.severity == "alta" for item in findings))


if __name__ == "__main__":
    unittest.main()
