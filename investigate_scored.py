import pandas as pd
from ai_hunt_agent import ThreatHuntAgent
from datetime import datetime
import os


# ============================================================
# SETUP
# ============================================================

RESULTS_DIR = "hunt01_results"

os.makedirs(RESULTS_DIR, exist_ok=True)


# ============================================================
# LOAD SCORED DATA
# ============================================================

df = pd.read_csv(
    f"{RESULTS_DIR}/scored_authentication_logs.csv"
)

df["timestamp"] = pd.to_datetime(df["timestamp"])


# ============================================================
# SELECT HIGH-RISK EVENTS
# ============================================================

investigation_events = (
    df[
        df["anomaly_score"] >= 40
    ]
    .sort_values(
        "anomaly_score",
        ascending=False
    )
)


columns = [
    "timestamp",
    "user",
    "src_ip",
    "dest_computer",
    "logon_type",
    "anomaly_score",
    "risk_level",
    "off_hours",
    "rare_ip",
    "unusual_user_ip",
    "rapid_multi_system"
]


evidence = investigation_events[
    columns
].to_string(index=False)


# ============================================================
# BUILD STATISTICAL SUMMARY
# ============================================================

total_events = len(df)

high_risk = len(
    df[df["anomaly_score"] >= 70]
)

medium_risk = len(
    df[
        (df["anomaly_score"] >= 40) &
        (df["anomaly_score"] < 70)
    ]
)

low_risk = len(
    df[df["anomaly_score"] < 40]
)

unique_users = df["user"].nunique()

unique_ips = df["src_ip"].nunique()

unique_computers = df["dest_computer"].nunique()


# ============================================================
# AI INVESTIGATION
# ============================================================

agent = ThreatHuntAgent()

question = """
Investigate Hunt #1: possible credential abuse and lateral movement.

The Python detection pipeline has already calculated anomaly scores.

IMPORTANT ANALYST RULES:

- Treat anomaly scores as detection signals, NOT proof.
- Only use facts contained in the evidence.
- Do not invent facts.
- Separate facts from hypotheses.
- Do not claim compromise is confirmed.
- 10.10.20.15 is an RFC1918 private address.
  Do NOT recommend public geolocation.
  Instead recommend identifying the internal asset,
  DHCP lease, hostname, owner, or network segment associated
  with that address.
- Logon Type 3 indicates a network logon, but does NOT by itself
  prove SMB or RDP.
- Do not map T1021.001 or T1021.002 unless the evidence
  identifies RDP or SMB specifically.

Analyze:

1. Off-hours authentication
2. Rare source IP
3. Unusual user/IP relationship
4. Rapid multi-system access
5. Domain controller targeting

Return exactly these sections:

FINDING

FACTS

ANOMALIES

BENIGN EXPLANATIONS

MALICIOUS HYPOTHESES

MITRE ATT&CK

CONFIDENCE

RECOMMENDED VALIDATION

FINAL ASSESSMENT
"""


result = agent.analyze(
    question,
    data_context=evidence
)


# ============================================================
# BUILD REPORT
# ============================================================

report = f"""
======================================================================
SOC-AI-HUNT
HUNT #1 — CREDENTIAL ABUSE INVESTIGATION
======================================================================

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

----------------------------------------------------------------------
DATASET SUMMARY
----------------------------------------------------------------------

Total authentication events: {total_events}
Unique users:                 {unique_users}
Unique source IPs:            {unique_ips}
Unique destination systems:   {unique_computers}

High-risk events (70+):       {high_risk}
Medium-risk events (40-69):   {medium_risk}
Low-risk events (<40):        {low_risk}


----------------------------------------------------------------------
HIGH / MEDIUM RISK EVIDENCE
----------------------------------------------------------------------

{evidence}


----------------------------------------------------------------------
AI-ASSISTED ANALYSIS
----------------------------------------------------------------------

{result}


----------------------------------------------------------------------
ANALYST NOTES
----------------------------------------------------------------------

This investigation uses a synthetic authentication dataset.

Anomaly scores are heuristic detection signals and do not represent
a probability of compromise.

AI-generated conclusions require human validation.

No compromise should be considered confirmed from this dataset alone.


----------------------------------------------------------------------
INVESTIGATION ARTIFACTS
----------------------------------------------------------------------

authentication_by_hour.png
authentication_by_ip.png
alice_authentication_timeline.png
scored_authentication_logs.csv
"""


# ============================================================
# SAVE REPORT
# ============================================================

report_path = (
    f"{RESULTS_DIR}/investigation_report.txt"
)

with open(
    report_path,
    "w",
    encoding="utf-8"
) as f:

    f.write(report)


# ============================================================
# DISPLAY
# ============================================================

print(report)

print("\n" + "=" * 70)
print("REPORT SAVED")
print("=" * 70)

print(report_path)