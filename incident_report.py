import pandas as pd
import requests
import json


MODEL = "qwen3:8b"
OLLAMA_URL = "http://localhost:11434/api/generate"


# ============================================================
# LOAD DATA
# ============================================================

auth = pd.read_csv(
    "hunt01_results/scored_authentication_logs.csv"
)

persistence = pd.read_csv(
    "persistence_scored.csv"
)

auth["timestamp"] = pd.to_datetime(auth["timestamp"])
persistence["timestamp"] = pd.to_datetime(
    persistence["timestamp"]
)


# ============================================================
# SELECT INCIDENT EVENTS
# ============================================================

auth_events = auth[
    (auth["user"] == "alice") &
    (auth["anomaly_score"] >= 70)
].sort_values("timestamp")


persistence_events = persistence[
    (persistence["user"] == "alice") &
    (persistence["anomaly_score"] >= 70)
].sort_values("timestamp")


# ============================================================
# BUILD TIMELINE
# ============================================================

timeline = []


for _, row in auth_events.iterrows():

    timeline.append({
        "timestamp": str(row["timestamp"]),
        "type": "Authentication",
        "user": row["user"],
        "source_ip": row["src_ip"],
        "target": row["dest_computer"],
        "score": int(row["anomaly_score"])
    })


for _, row in persistence_events.iterrows():

    timeline.append({
        "timestamp": str(row["timestamp"]),
        "type": "Persistence",
        "user": row["user"],
        "host": row["host"],
        "mechanism": row["mechanism"],
        "name": row["name"],
        "command": row["command"],
        "score": int(row["anomaly_score"])
    })


timeline = sorted(
    timeline,
    key=lambda x: x["timestamp"]
)


# ============================================================
# PRINT TIMELINE
# ============================================================

print("=" * 80)
print("SOC-AI-HUNT — INCIDENT TIMELINE")
print("=" * 80)

for event in timeline:

    print(json.dumps(event, indent=2))


# ============================================================
# AI PROMPT
# ============================================================

prompt = f"""
You are a senior SOC analyst.

Analyze the following correlated security events.

IMPORTANT:
Separate FACTS from HYPOTHESES.
Do not claim that an attack is confirmed unless the evidence proves it.

INCIDENT TIMELINE:

{json.dumps(timeline, indent=2)}

Produce a professional SOC incident assessment with these sections:

1. EXECUTIVE SUMMARY

2. ATTACK TIMELINE
Explain the sequence chronologically.

3. CONFIRMED FACTS
Only state what the logs directly prove.

4. SUSPICIOUS INDICATORS
Explain why the activity is anomalous.

5. POSSIBLE ATTACK CHAIN
Explain the most likely sequence of attacker behavior,
but clearly label it as a hypothesis.

6. MITRE ATT&CK
Map only techniques supported by the evidence.
Do not invent technique IDs.

7. BENIGN EXPLANATIONS
Give realistic legitimate explanations.

8. CONFIDENCE
Choose LOW, MEDIUM, or HIGH and explain why.

9. RECOMMENDED SOC ACTIONS
Give practical defensive investigation steps.

10. FINAL ASSESSMENT
State whether this should be treated as:
- Benign
- Suspicious
- Likely Malicious
- Confirmed Malicious

Be precise and conservative.
"""


# ============================================================
# SEND TO OLLAMA
# ============================================================

print("\n" + "=" * 80)
print("AI INCIDENT ANALYSIS")
print("=" * 80)


response = requests.post(
    OLLAMA_URL,
    json={
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    },
    timeout=300
)


response.raise_for_status()

result = response.json()

print(result["response"])


# ============================================================
# SAVE REPORT
# ============================================================

with open(
    "final_incident_report.txt",
    "w",
    encoding="utf-8"
) as f:

    f.write(result["response"])


print("\n" + "=" * 80)
print("REPORT SAVED")
print("=" * 80)

print("final_incident_report.txt")