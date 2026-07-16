import json
import argparse
import logging
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

PROJECT_ID    = "project-9ee54ebd-22e7-4831-9cd"
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "http://localhost:8088/services/collector/event")
SPLUNK_TOKEN   = os.getenv("SPLUNK_TOKEN",   "5b3b723f-52d4-4907-9bfa-a1643446dae2")
SPLUNK_INDEX   = os.getenv("SPLUNK_INDEX",   "main")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("gcp-splunk-forwarder")


# ──────────────────────────────────────────────
# FORWARDER
# ──────────────────────────────────────────────

class GCPSplunkForwarder:

    def __init__(self):
        from google.cloud import logging as gcp_logging
        self.gcp_client = gcp_logging.Client(project=PROJECT_ID)
        self.splunk_url  = SPLUNK_HEC_URL
        self.headers     = {
            "Authorization": f"Splunk {SPLUNK_TOKEN}",
            "Content-Type":  "application/json",
        }
        log.info(f"GCP project  : {PROJECT_ID}")
        log.info(f"Splunk HEC   : {self.splunk_url}")

    def fetch_logs(self, hours: int = 1) -> list:
        since     = datetime.now(timezone.utc) - timedelta(hours=hours)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        filter_str = f"""
            logName="projects/{PROJECT_ID}/logs/cloudaudit.googleapis.com%2Factivity"
            timestamp>="{since_str}"
        """

        entries = []
        for entry in self.gcp_client.list_entries(
            filter_=filter_str,
            order_by="timestamp asc",
            page_size=500,
        ):
            entries.append(entry)

        log.info(f"Fetched {len(entries)} audit log entries from GCP")
        return entries

    def _parse_entry(self, entry) -> dict:
        payload = entry.payload if hasattr(entry, 'payload') else {}
        if hasattr(payload, '_pb'):
            from google.protobuf.json_format import MessageToDict
            payload = MessageToDict(payload._pb)

        return {
            "timestamp":   str(entry.timestamp),
            "severity":    str(entry.severity) if entry.severity else "DEFAULT",
            "method":      payload.get("methodName", ""),
            "service":     payload.get("serviceName", ""),
            "principal":   payload.get("authenticationInfo", {}).get("principalEmail", "unknown"),
            "caller_ip":   payload.get("requestMetadata", {}).get("callerIp", "unknown"),
            "resource":    payload.get("resourceName", ""),
            "policy_delta": payload.get("serviceData", {}).get("policyDelta", {}),
            "status_code": payload.get("status", {}).get("code", 0),
            "project_id":  PROJECT_ID,
            "log_source":  "gcp_cloud_audit",
        }

    def send_to_splunk(self, event: dict) -> bool:
        # Parse timestamp for Splunk
        try:
            ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            epoch = ts.timestamp()
        except Exception:
            epoch = datetime.now().timestamp()

        payload = {
            "time":       epoch,
            "host":       "gcp-audit",
            "source":     "gcp:cloudaudit",
            "sourcetype": "_json",
            "index":      SPLUNK_INDEX,
            "event":      event,
        }

        try:
            r = requests.post(
                self.splunk_url,
                headers=self.headers,
                data=json.dumps(payload),
                timeout=10,
            )
            if r.status_code == 200:
                return True
            else:
                log.warning(f"Splunk HEC returned {r.status_code}: {r.text}")
                return False
        except Exception as e:
            log.error(f"Failed to send to Splunk: {e}")
            return False

    def forward(self, hours: int = 1):
        log.info(f"=== GCP → Splunk Forwarder Starting (last {hours}h) ===")

        entries = self.fetch_logs(hours=hours)
        if not entries:
            log.warning("No log entries found.")
            return

        sent    = 0
        failed  = 0

        for entry in entries:
            event = self._parse_entry(entry)
            if self.send_to_splunk(event):
                sent += 1
            else:
                failed += 1

        log.info(f"=== Forwarding Complete: {sent} sent, {failed} failed ===")
        log.info(f"Search in Splunk: index=main source=\"gcp:cloudaudit\"")
        return sent, failed


# ──────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GCP → Splunk Log Forwarder")
    parser.add_argument("--hours", type=int, default=1, help="Hours of logs to forward")
    args = parser.parse_args()

    forwarder = GCPSplunkForwarder()
    forwarder.forward(hours=args.hours)


if __name__ == "__main__":
    main()