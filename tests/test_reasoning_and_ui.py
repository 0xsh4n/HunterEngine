from ai.local_reasoner import LocalAIConfig, LocalAIReasoner, SEVERITY_ORDER
from main import print_results


class DemoState:
    def __init__(self):
        self.subdomains = None
        self.live_hosts = None
        self.endpoints = None
        self.js_files = None
        self.findings = [
            {
                "title": "Potential IDOR",
                "severity": "high",
                "confidence": 0.82,
                "detector": "idor_detector",
                "url": "https://example.test/api/orders/1",
            }
        ]
        self.weak_signals = []
        self.chained_findings = None
        self.errors = [None, "transient parse issue"]


def test_print_results_handles_malformed_state_without_crashing(capsys):
    print_results(DemoState(), 12.3)
    captured = capsys.readouterr()
    assert "Scan Complete" in captured.out
    assert "Potential IDOR" in captured.out


def test_fallback_reasoning_is_conservative_and_actionable():
    reasoner = LocalAIReasoner(LocalAIConfig(enabled=True))
    finding = {
        "title": "Broken access control",
        "description": "The endpoint exposes an order id and returns data for other accounts.",
        "confidence": 0.74,
        "url": "https://example.test/api/orders/1",
        "parameter": "id",
    }
    analysis = reasoner._fallback_analysis(
        finding,
        {"endpoint_count": 9, "weak_signal_count": 1, "sample_live_hosts": ["example.test"]},
    )

    assert analysis["plausible"] is True
    assert analysis["false_positive_risk"] in {"low", "medium", "high"}
    assert analysis["severity"] in SEVERITY_ORDER
    assert analysis["confidence_delta"] <= 0.25
    assert analysis["recommended_validation"]
    assert analysis["remediation"]
