import pandas as pd
from ai_hunt_agent import ThreatHuntAgent


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv("persistence_logs.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hour"] = df["timestamp"].dt.hour


# ============================================================
# SELECT INTERESTING EVENTS
# ============================================================

interesting = df[
    (
        (df["hour"] < 7) |
        (df["hour"] > 20)
    )
    |
    (
        df["command"].str.contains(
            "powershell|enc|ExecutionPolicy Bypass|hidden|Users\\\\Public",
            case=False,
            na=False
        )
    )
]


evidence = interesting.to_string(
    index=False
)


# ============================================================
# AI INVESTIGATION
# ============================================================

agent = ThreatHuntAgent()


question = """
You are investigating Hunt #2: possible persistence.

Analyze the persistence events provided below.

Focus on:

1. Off-hours persistence creation
2. PowerShell execution
3. Encoded PowerShell
4. ExecutionPolicy Bypass
5. Hidden PowerShell
6. Executables in Users\\Public
7. Multiple persistence mechanisms
8. Multiple persistence mechanisms appearing on the same host
   within a short time period

IMPORTANT:

- Separate FACTS from HYPOTHESES.
- Do not invent evidence.
- Do not claim malware is confirmed.
- PowerShell itself is not automatically malicious.
- A scheduled task, registry run key, or service can be legitimate.
- Explain why the combination of behaviors is suspicious.

MITRE ATT&CK guidance:

T1053.005 - Scheduled Task/Job: Scheduled Task
Use when a scheduled task is observed.

T1547.001 - Registry Run Keys / Startup Folder
Use when a Registry Run Key is observed.

T1543.003 - Create or Modify System Process: Windows Service
Use when a Windows service is observed.

T1059.001 - Command and Scripting Interpreter: PowerShell
Use when PowerShell execution is directly observed.

T1027 - Obfuscated/Compressed Files and Information
Use cautiously when encoded/obfuscated content is observed.

Do not invent additional ATT&CK techniques.

Return:

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


print("\n" + "=" * 70)
print("AI-ASSISTED HUNT #2 INVESTIGATION")
print("=" * 70)

print(result)