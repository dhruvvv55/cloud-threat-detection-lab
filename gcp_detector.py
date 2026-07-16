"""
GCP Cloud Detection Lab — IAM Threat Detector
==============================================
Author : Dhruv Patel
Stack  : Python 3.9+, Google Cloud Logging API

Detections:
  1. IAM Privilege Escalation — service account granted owner/admin role
  2. Anomalous Service Account Activity — SA calling sensitive APIs
  3. Unauthorized IAM Policy Changes — policy modified outside change window
  4. Service Account Key Creation — potential credential theft

Usage:
  python gcp_detector.py
  python gcp_detector.py --hours 24
  python gcp_detector.py --output report.json
"""

import json
import argparse
import logging
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import defaultdict

from google.cloud import logging as gcp_logging
from google.cloud.logging_v2 import Client

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

PROJECT_ID = "project-9ee54ebd-22e7-4831-9cd"

# Roles considered high privilege
HIGH_PRIV_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/resourcemanager.projectIamAdmin",
    "roles/compute.admin",
    "roles/storage.admin",
}

# Methods that indicate sensitive IAM activity
SENSITIVE_METHODS = {
    "SetIamPolicy",
    "CreateServiceAccountKey",
    "DeleteServiceAccountKey",
    "SignBlob",
    "SignJwt",
    "CreateServiceAccount",
    "DeleteServiceAccount",
    "DisableServiceAccount",
    "EnableServiceAccount",
    "UpdateServiceAccount",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("gcp-detector")


# ──────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────

@dataclass
class ThreatFinding:
    finding_id:    str
    timestamp:     str
    severity:      str          # CRITICAL / HIGH / MEDIUM / LOW
    detection:     str          # Detection rule name
    description:   str
    principal:     str          # Who did it
    caller_ip:     str          # From where
    method:        str          # What API call
    resource:      str          # What resource
    evidence:      dict = field(default_factory=dict)
    mitre_tactic:  str = ""
    mitre_technique: str = ""
    recommended_action: str = ""


@dataclass
class DetectionReport:
    generated_at:     str
    project_id:       str
    window_hours:     int
    total_events:     int
    total_findings:   int
    critical_count:   int
    high_count:       int
    medium_count:     int
    findings:         list
    mitre_coverage:   dict
    analyst_summary:  str


# ──────────────────────────────────────────────
# LOG COLLECTOR
# ──────────────────────────────────────────────

class GCPLogCollector:
    """Fetches Cloud Audit Logs from GCP."""

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.client = Client(project=project_id)
        log.info(f"Connected to GCP project: {project_id}")

    def fetch_audit_logs(self, hours: int = 1) -> list:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours))
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        filter_str = f"""
            logName="projects/{self.project_id}/logs/cloudaudit.googleapis.com%2Factivity"
            timestamp>="{since_str}"
        """

        entries = []
        try:
            for entry in self.client.list_entries(
                filter_=filter_str,
                order_by="timestamp desc",
                page_size=500,
            ):
                entries.append(entry)
            log.info(f"Fetched {len(entries)} audit log entries")
        except Exception as e:
            log.error(f"Failed to fetch logs: {e}")

        return entries

    def parse_entry(self, entry) -> dict:
        """Parse a log entry into a flat dict."""
        payload = entry.payload if hasattr(entry, 'payload') else {}

        # Handle proto payload
        if hasattr(payload, '_pb'):
            import json as _json
            from google.protobuf.json_format import MessageToDict
            payload = MessageToDict(payload._pb)

        return {
            "timestamp":      str(entry.timestamp),
            "severity":       str(entry.severity) if entry.severity else "DEFAULT",
            "method":         payload.get("methodName", ""),
            "service":        payload.get("serviceName", ""),
            "principal":      payload.get("authenticationInfo", {}).get("principalEmail", "unknown"),
            "caller_ip":      payload.get("requestMetadata", {}).get("callerIp", "unknown"),
            "resource":       payload.get("resourceName", ""),
            "status_code":    payload.get("status", {}).get("code", 0),
            "request":        payload.get("request", {}),
            "response":       payload.get("response", {}),
            "policy_delta":   payload.get("serviceData", {}).get("policyDelta", {}),
            "raw":            payload,
        }


# ──────────────────────────────────────────────
# DETECTION ENGINE
# ──────────────────────────────────────────────

class IAMThreatDetector:
    """Detection rules for GCP IAM threats."""

    def __init__(self):
        self.findings = []

    def analyze(self, events: list) -> list:
        for event in events:
            self._detect_privilege_escalation(event)
            self._detect_service_account_key_creation(event)
            self._detect_anomalous_sa_activity(event)
            self._detect_policy_change(event)

        log.info(f"Detection complete: {len(self.findings)} findings")
        return self.findings

    def _detect_privilege_escalation(self, event: dict):
        """Detect when a service account is granted a high-privilege role."""
        if event["method"] != "SetIamPolicy":
            return

        delta = event.get("policy_delta", {})
        binding_deltas = delta.get("bindingDeltas", [])

        for bd in binding_deltas:
            if bd.get("action") != "ADD":
                continue

            role   = bd.get("role", "")
            member = bd.get("member", "")

            if role not in HIGH_PRIV_ROLES:
                continue

            # Extra severity if it's a service account getting owner
            is_sa     = member.startswith("serviceAccount:")
            severity  = "CRITICAL" if (is_sa and role == "roles/owner") else "HIGH"

            self.findings.append(ThreatFinding(
                finding_id   = f"PRIV-ESC-{len(self.findings)+1:03d}",
                timestamp    = event["timestamp"],
                severity     = severity,
                detection    = "IAM Privilege Escalation",
                description  = f"Principal '{event['principal']}' granted '{role}' to '{member}'",
                principal    = event["principal"],
                caller_ip    = event["caller_ip"],
                method       = event["method"],
                resource     = event["resource"],
                evidence     = {"role": role, "member": member, "action": "ADD"},
                mitre_tactic = "Privilege Escalation",
                mitre_technique = "T1078.004 — Valid Accounts: Cloud Accounts",
                recommended_action = (
                    f"Immediately revoke '{role}' from '{member}'. "
                    "Investigate why this change was made. "
                    "Check for other IAM changes from the same principal."
                ),
            ))

    def _detect_service_account_key_creation(self, event: dict):
        """Detect service account key creation — potential credential theft setup."""
        if event["method"] != "CreateServiceAccountKey":
            return

        self.findings.append(ThreatFinding(
            finding_id   = f"SA-KEY-{len(self.findings)+1:03d}",
            timestamp    = event["timestamp"],
            severity     = "HIGH",
            detection    = "Service Account Key Creation",
            description  = f"New key created for SA by '{event['principal']}' from {event['caller_ip']}",
            principal    = event["principal"],
            caller_ip    = event["caller_ip"],
            method       = event["method"],
            resource     = event["resource"],
            evidence     = {"resource": event["resource"]},
            mitre_tactic = "Credential Access",
            mitre_technique = "T1528 — Steal Application Access Token",
            recommended_action = (
                "Verify key creation was authorized. "
                "If unexpected, revoke the key immediately via: "
                "gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL"
            ),
        ))

    def _detect_anomalous_sa_activity(self, event: dict):
        """Detect service accounts calling sensitive APIs."""
        principal = event.get("principal", "")
        method    = event.get("method", "")

        if not principal.endswith(".gserviceaccount.com"):
            return
        if method not in SENSITIVE_METHODS:
            return
        if method in ("SetIamPolicy", "CreateServiceAccountKey"):
            return  # Already covered above

        self.findings.append(ThreatFinding(
            finding_id   = f"SA-ANOM-{len(self.findings)+1:03d}",
            timestamp    = event["timestamp"],
            severity     = "MEDIUM",
            detection    = "Anomalous Service Account Activity",
            description  = f"Service account '{principal}' called sensitive API '{method}'",
            principal    = principal,
            caller_ip    = event["caller_ip"],
            method       = method,
            resource     = event["resource"],
            evidence     = {"method": method, "service": event["service"]},
            mitre_tactic = "Defense Evasion",
            mitre_technique = "T1078.004 — Valid Accounts: Cloud Accounts",
            recommended_action = (
                f"Review whether SA '{principal}' should have permission to call '{method}'. "
                "Apply principle of least privilege — remove unnecessary permissions."
            ),
        ))

    def _detect_policy_change(self, event: dict):
        """Detect any IAM policy modification as medium severity for audit."""
        if event["method"] != "SetIamPolicy":
            return

        # Only flag if not already caught by privilege escalation
        delta         = event.get("policy_delta", {})
        binding_deltas = delta.get("bindingDeltas", [])
        high_priv     = any(bd.get("role", "") in HIGH_PRIV_ROLES
                            for bd in binding_deltas if bd.get("action") == "ADD")
        if high_priv:
            return  # Already flagged as CRITICAL/HIGH

        self.findings.append(ThreatFinding(
            finding_id   = f"POLICY-{len(self.findings)+1:03d}",
            timestamp    = event["timestamp"],
            severity     = "LOW",
            detection    = "IAM Policy Modification",
            description  = f"IAM policy modified by '{event['principal']}' on '{event['resource']}'",
            principal    = event["principal"],
            caller_ip    = event["caller_ip"],
            method       = event["method"],
            resource     = event["resource"],
            evidence     = {"deltas": binding_deltas},
            mitre_tactic = "Persistence",
            mitre_technique = "T1098 — Account Manipulation",
            recommended_action = "Review IAM policy change for legitimacy. Ensure change is documented.",
        ))


# ──────────────────────────────────────────────
# REPORTER
# ──────────────────────────────────────────────

class DetectionReporter:

    def generate(self, findings: list, total_events: int, hours: int) -> DetectionReport:
        counts     = defaultdict(int)
        mitre_freq = defaultdict(int)

        for f in findings:
            counts[f.severity] += 1
            if f.mitre_technique:
                mitre_freq[f.mitre_technique] += 1

        summary = self._build_summary(findings, counts)

        return DetectionReport(
            generated_at   = datetime.now(timezone.utc).isoformat(),
            project_id     = PROJECT_ID,
            window_hours   = hours,
            total_events   = total_events,
            total_findings = len(findings),
            critical_count = counts["CRITICAL"],
            high_count     = counts["HIGH"],
            medium_count   = counts["MEDIUM"],
            findings       = [asdict(f) for f in findings],
            mitre_coverage = dict(sorted(mitre_freq.items(),
                                         key=lambda x: x[1], reverse=True)),
            analyst_summary = summary,
        )

    def _build_summary(self, findings: list, counts: dict) -> str:
        lines = [
            f"Total findings: {len(findings)}",
            f"Critical: {counts['CRITICAL']} | High: {counts['HIGH']} | "
            f"Medium: {counts['MEDIUM']} | Low: {counts['LOW']}",
        ]

        detections = {f.detection for f in findings}
        if "IAM Privilege Escalation" in detections:
            lines.append("\n⚠ IAM Privilege Escalation detected — possible account takeover or insider threat")
        if "Service Account Key Creation" in detections:
            lines.append("⚠ Service Account key created — potential credential exfiltration setup")
        if "Anomalous Service Account Activity" in detections:
            lines.append("⚠ Service Account calling sensitive APIs — review SA permissions")

        return "\n".join(lines)

    def print_report(self, report: DetectionReport):
        sep = "=" * 60
        print(f"\n{sep}")
        print("  GCP CLOUD THREAT DETECTION REPORT")
        print(sep)
        print(f"  Project   : {report.project_id}")
        print(f"  Generated : {report.generated_at}")
        print(f"  Window    : Last {report.window_hours}h")
        print(f"\n  Total Events    : {report.total_events}")
        print(f"  Total Findings  : {report.total_findings}")
        print(f"  Critical        : {report.critical_count}")
        print(f"  High            : {report.high_count}")
        print(f"  Medium          : {report.medium_count}")

        if report.findings:
            print(f"\n{'-'*60}")
            print("  THREAT FINDINGS")
            print(f"{'-'*60}")
            for f in report.findings:
                print(f"\n  [{f['severity']:<8}] {f['detection']}")
                print(f"  ID        : {f['finding_id']}")
                print(f"  Time      : {f['timestamp']}")
                print(f"  Principal : {f['principal']}")
                print(f"  Caller IP : {f['caller_ip']}")
                print(f"  Method    : {f['method']}")
                print(f"  MITRE     : {f['mitre_technique']}")
                print(f"  Description: {f['description']}")
                print(f"  Action    : {f['recommended_action']}")

        print(f"\n{'-'*60}")
        print("  MITRE ATT&CK COVERAGE")
        print(f"{'-'*60}")
        for technique, count in report.mitre_coverage.items():
            print(f"  {technique:<50} {count} finding(s)")

        print(f"\n{'-'*60}")
        print("  ANALYST SUMMARY")
        print(f"{'-'*60}")
        for line in report.analyst_summary.split("\n"):
            print(f"  {line}")
        print(f"\n{sep}\n")


# ──────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GCP IAM Threat Detector")
    parser.add_argument("--hours",  type=int, default=1,    help="Hours of logs to analyze")
    parser.add_argument("--output", type=str, default=None, help="Save report to JSON file")
    args = parser.parse_args()

    log.info("=== GCP Detection Pipeline Starting ===")
    log.info(f"Project: {PROJECT_ID} | Window: {args.hours}h")

    # Collect
    collector = GCPLogCollector(PROJECT_ID)
    entries   = collector.fetch_audit_logs(hours=args.hours)

    if not entries:
        log.warning("No audit log entries found in window.")
        return

    # Parse
    events = [collector.parse_entry(e) for e in entries]
    log.info(f"Parsed {len(events)} events")

    # Detect
    detector = IAMThreatDetector()
    findings = detector.analyze(events)

    # Report
    reporter = DetectionReporter()
    report   = reporter.generate(findings, len(events), args.hours)
    reporter.print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(asdict(report) if hasattr(report, '__dataclass_fields__') 
                     else report.__dict__, f, indent=2, default=str)
        log.info(f"Report saved to {args.output}")

    log.info("=== Detection Complete ===")


if __name__ == "__main__":
    main()