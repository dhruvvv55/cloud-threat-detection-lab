# Cloud Threat Detection Lab

Simulated IAM attack scenarios on GCP, detected using a Python pipeline and Splunk SPL rules.

## Architecture

![Architecture](assets/architecture.svg)

## What I Did

Set up a GCP project, created a low-privilege service account, then simulated an attacker escalating it to `roles/owner` via `SetIamPolicy`. GCP Cloud Audit Logs captured every API call. From there I built two things:

1. **gcp_detector.py** — pulls audit logs via the Cloud Logging API, runs detection rules, maps findings to MITRE ATT&CK, and outputs a structured incident report
2. **gcp_to_splunk.py** — forwards those same logs into Splunk via HEC, where I wrote SPL detection queries and set up a scheduled hourly alert

## Attack Scenarios

**IAM Privilege Escalation (T1078.004)**

Created a service account with viewer-only access, then granted it `roles/owner`:

```bash
# Low privilege to start
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:attacker-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"

# Escalate to owner
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:attacker-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/owner"
```

Cloud Audit Logs recorded the `SetIamPolicy` call with the caller IP, principal, and exact policy delta.

## Detection Rules (Python)

| Severity | Rule | MITRE |
|---|---|---|
| CRITICAL | IAM Privilege Escalation | T1078.004 |
| HIGH | Service Account Key Creation | T1528 |
| MEDIUM | Anomalous SA API Activity | T1078.004 |
| LOW | IAM Policy Modification | T1098 |

Sample output from `gcp_detector.py`:

```
[CRITICAL] IAM Privilege Escalation
ID        : PRIV-ESC-001
Principal : attacker@gmail.com
Caller IP : 34.124.220.91
Method    : SetIamPolicy
MITRE     : T1078.004 - Valid Accounts: Cloud Accounts
Action    : Revoke roles/owner. Check for lateral movement.
```

## Splunk Integration

Forwarded 22 real GCP audit log events into Splunk via HEC. Detection query:

```spl
index=main source="gcp:cloudaudit" method="SetIamPolicy"
| eval severity="CRITICAL", mitre="T1078.004 - Valid Accounts: Cloud Accounts"
| table timestamp, principal, caller_ip, method, severity, mitre
| sort -timestamp
```

Saved as a scheduled hourly Splunk alert that triggers when results > 0.

## Stack

- GCP Cloud Audit Logs
- Python 3.9+ / google-cloud-logging
- Splunk Enterprise (local) / HEC
- SPL

## Setup

```bash
# Auth
gcloud auth application-default login
gcloud auth application-default set-quota-project YOUR_PROJECT_ID

# Install
pip install google-cloud-logging google-auth python-dotenv requests

# Run detector
python gcp_detector.py --hours 1

# Forward to Splunk
python gcp_to_splunk.py --hours 1
```

## Author

**Dhruv Patel** — MS Cybersecurity Engineering, USC
[LinkedIn](https://linkedin.com/in/dhruvvv55) · [SOC Lab](https://github.com/dhruvvv55/soc-home-lab)
