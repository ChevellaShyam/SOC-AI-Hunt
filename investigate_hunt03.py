import pandas as pd

df = pd.read_csv("process_execution_logs.csv")

print("=" * 80)
print("AI-ASSISTED HUNT #3 — PROCESS EXECUTION INVESTIGATION")
print("=" * 80)

print("\nHIGH-RISK PROCESS EVENTS")
print("-" * 80)

high = df[df["anomaly_score"] >= 70].sort_values("timestamp")

if high.empty:
    print("No high-risk events found.")
else:
    print(
        high[
            [
                "timestamp",
                "host",
                "user",
                "process",
                "command",
                "parent_process",
                "anomaly_score",
                "risk_level",
            ]
        ].to_string(index=False)
    )

print("\n\nFACTS")
print("-" * 80)

print("""
- WS07 executed PowerShell under user 'alice' during off-hours.
- One PowerShell command used ExecutionPolicy Bypass.
- One PowerShell command used an encoded command and hidden window.
- Executables were launched from C:\\Users\\Public\\.
- The suspicious executions occurred within approximately 5 minutes.
""")

print("\nANOMALIES")
print("-" * 80)

print("""
- PowerShell with ExecutionPolicy Bypass
- Encoded PowerShell
- Hidden PowerShell execution
- Executables in C:\\Users\\Public\\
- Multiple suspicious processes on the same host
- Off-hours execution
""")

print("\nBENIGN EXPLANATIONS")
print("-" * 80)

print("""
- Legitimate administrative scripting
- Scheduled maintenance
- Internal automation
- Software update activity
""")

print("\nMALICIOUS HYPOTHESES")
print("-" * 80)

print("""
- Malicious PowerShell execution
- Execution of a downloaded payload
- Persistence payload execution
- Defense evasion through encoding and hidden windows
- Masquerading through names such as svchost.exe
""")

print("\nMITRE ATT&CK")
print("-" * 80)

print("""
T1059.001 - Command and Scripting Interpreter: PowerShell
T1027    - Obfuscated/Compressed Files and Information
T1564.001 - Hide Artifacts: Hidden Window
T1036    - Masquerading
""")

print("\nCONFIDENCE")
print("-" * 80)

print("HIGH")

print("""
The process telemetry directly connects suspicious PowerShell
execution and non-standard executable locations to WS07.
""")

print("\nFINAL ASSESSMENT")
print("-" * 80)

print("""
SUSPICIOUS

Process execution provides stronger evidence than authentication
alone. The combination of encoded/hidden PowerShell, ExecutionPolicy
Bypass, off-hours activity, and executables in C:\\Users\\Public\\
is consistent with potential malicious execution.

This remains an investigation finding rather than proof of malware,
because the actual binaries and complete PowerShell payload are
not available.
""")

print("=" * 80)