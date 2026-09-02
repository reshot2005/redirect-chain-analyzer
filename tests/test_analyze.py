"""Tests."""

from pathlib import Path

from redirect_chain_analyzer.core import analyze_har

FIXTURES = Path(__file__).resolve().parent.parent / "sample_data"


class TestRedirectChainAnalyzer:
    def test_traces_chains(self) -> None:
        r = analyze_har(FIXTURES / "sample_har_entries.json")
        assert len(r.chains) >= 1

    def test_finds_open_redirect(self) -> None:
        r = analyze_har(FIXTURES / "sample_har_entries.json")
        assert any(i.issue == "open_redirect" for i in r.issues)

    def test_finds_https_downgrade(self) -> None:
        r = analyze_har(FIXTURES / "sample_har_entries.json")
        assert any(i.issue == "https_downgrade" for i in r.issues)
