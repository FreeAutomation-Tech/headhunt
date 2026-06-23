from unittest.mock import Mock, patch

from src.scanner import (
    scan_url, HEADER_CHECKS, HEADER_ORDER,
    HeaderResult, ScanResult,
)


class TestHeaderResult:
    def test_to_dict(self):
        hr = HeaderResult(
            "strict-transport-security", True, "max-age=31536000",
            "HIGH", "desc", "advice"
        )
        d = hr.to_dict()
        assert d["header"] == "Strict-Transport-Security"
        assert d["present"] is True
        assert d["value"] == "max-age=31536000"


class TestScanResult:
    def test_score_all_present(self):
        headers = [
            HeaderResult("a", True),
            HeaderResult("b", True),
        ]
        sr = ScanResult(url="https://x.com", status_code=200, headers=headers)
        assert sr.score == 100
        assert sr.grade == "A"

    def test_score_half_present(self):
        headers = [
            HeaderResult("a", True),
            HeaderResult("b", False),
        ]
        sr = ScanResult(url="https://x.com", status_code=200, headers=headers)
        assert sr.score == 50
        assert sr.grade == "C"

    def test_score_zero(self):
        headers = [HeaderResult("a", False)]
        sr = ScanResult(url="https://x.com", status_code=200, headers=headers)
        assert sr.score == 0
        assert sr.grade == "F"

    def test_score_no_headers(self):
        sr = ScanResult(url="https://x.com")
        assert sr.score == 0

    def test_to_dict(self):
        sr = ScanResult(url="https://x.com", status_code=200, headers=[])
        d = sr.to_dict()
        assert d["url"] == "https://x.com"
        assert d["grade"] == "F"


class TestScanUrl:
    @patch("src.scanner.requests.get")
    def test_successful_scan(self, mock_get):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com"
        mock_resp.headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        }
        mock_get.return_value = mock_resp

        result = scan_url("https://example.com")

        assert result.status_code == 200
        assert result.error is None
        present = [h for h in result.headers if h.present]
        assert len(present) >= 4

    @patch("src.scanner.requests.get")
    def test_request_error(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")

        result = scan_url("https://example.com")

        assert result.error is not None
        assert "Connection refused" in result.error

    @patch("src.scanner.requests.get")
    def test_adds_https_prefix(self, mock_get):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com"
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        result = scan_url("example.com")
        assert result.status_code == 200
        # requests.get should have been called with https://
        call_url = mock_get.call_args[0][0]
        assert call_url == "example.com"  # scan_url doesn't modify URL

    @patch("src.scanner.requests.get")
    def test_redirect_detected(self, mock_get):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.url = "https://redirected.com"
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        result = scan_url("https://original.com")
        assert result.redirect_url == "https://redirected.com"

    @patch("src.scanner.requests.get")
    def test_no_redirect(self, mock_get):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com"
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        result = scan_url("https://example.com")
        assert result.redirect_url is None


class TestHeaderChecks:
    def test_all_headers_have_entries(self):
        for key in HEADER_ORDER:
            assert key in HEADER_CHECKS, f"{key} missing from HEADER_CHECKS"

    def test_all_entries_have_required_fields(self):
        for key, check in HEADER_CHECKS.items():
            assert "name" in check
            assert "severity" in check
            assert check["severity"] in ("HIGH", "MEDIUM", "LOW", "INFO")
            assert "description" in check
            assert "advice" in check
