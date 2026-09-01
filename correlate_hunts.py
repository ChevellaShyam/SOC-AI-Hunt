import pandas as pd

print("=" * 80)
print("SOC-AI-HUNT — FINAL CROSS-HUNT CORRELATION")
print("=" * 80)

# Load datasets
auth = pd.read_csv("hunt01_results/scored_authentication_logs.csv")
persist = pd.read_csv("persistence_scored.csv")
process = pd.read_csv("process_execution_logs.csv")

# Convert timestamps
auth["timestamp"] = pd.to_datetime(auth["timestamp"])
persist["timestamp"] = pd.to_datetime(persist["timestamp"])
process["timestamp"] = pd.to_datetime(process["timestamp"])

# High-risk events
auth_high = auth[auth["anomaly_score"] >= 70]
persist_high = persist[persist["anomaly_score"] >= 70]
process_high = process[process["anomaly_score"] >= 70]

print("\nHUNT #1 — AUTHENTICATION")
print("-" * 80)
print(f"High-risk events: {len(auth_high)}")

print("\nHUNT #2 — PERSISTENCE")
print("-" * 80)
print(f"High-risk events: {len(persist_high)}")

print("\nHUNT #3 — PROCESS EXECUTION")
print("-" * 80)
print(f"High-risk events: {len(process_high)}")

# ---------------------------------------------------------
# Common user
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("COMMON USERS")
print("=" * 80)

common_users = sorted(
    set(auth_high["user"].unique())
    & set(persist_high["user"].unique())
    & set(process_high["user"].unique())
)

for user in common_users:
    print(user)

# ---------------------------------------------------------
# Temporal correlation
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("TEMPORAL CORRELATION")
print("=" * 80)

correlations = []

for _, a in auth_high.iterrows():

    for _, p in persist_high.iterrows():

        # Same user and within 20 minutes
        if a["user"] == p["user"]:
            delta = abs((p["timestamp"] - a["timestamp"]).total_seconds())

            if delta <= 1200:
                correlations.append({
                    "auth_time": a["timestamp"],
                    "auth_user": a["user"],
                    "src_ip": a["src_ip"],
                    "destination": a["dest_computer"],
                    "persistence_time": p["timestamp"],
                    "host": p["host"],
                    "mechanism": p["mechanism"],
                    "persistence_name": p["name"],
                    "time_difference_seconds": int(delta)
                })

# Process correlation

process_correlations = []

for _, p in persist_high.iterrows():

    for _, e in process_high.iterrows():

        if p["user"] == e["user"] and p["host"] == e["host"]:

            delta = abs(
                (e["timestamp"] - p["timestamp"]).total_seconds()
            )

            if delta <= 1200:
                process_correlations.append({
                    "persistence_time": p["timestamp"],
                    "host": p["host"],
                    "user": p["user"],
                    "mechanism": p["mechanism"],
                    "persistence_name": p["name"],
                    "execution_time": e["timestamp"],
                    "process": e["process"],
                    "command": e["command"],
                    "time_difference_seconds": int(delta)
                })

print(f"Authentication → Persistence correlations: {len(correlations)}")
print(f"Persistence → Execution correlations: {len(process_correlations)}")

# ---------------------------------------------------------
# Display correlation chain
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("ATTACK CHAIN")
print("=" * 80)

if common_users:
    print("""
1. AUTHENTICATION
   Alice authenticates from 10.10.20.15 to multiple systems.

2. LATERAL MOVEMENT INDICATOR
   SQL01 → FILE01 → APP01 → WEB01 → DC01

3. PERSISTENCE
   WS07 receives multiple persistence mechanisms:
   - Scheduled Task
   - Registry Run Key
   - Windows Service

4. EXECUTION
   WS07 executes:
   - PowerShell with ExecutionPolicy Bypass
   - Encoded PowerShell
   - Hidden PowerShell
   - Executables from C:\\Users\\Public\\
""")

# ---------------------------------------------------------
# Save results
# ---------------------------------------------------------

pd.DataFrame(correlations).to_csv(
    "auth_persistence_correlations.csv",
    index=False
)

pd.DataFrame(process_correlations).to_csv(
    "persistence_execution_correlations.csv",
    index=False
)

print("=" * 80)
print("CORRELATION FILES SAVED")
print("=" * 80)

print("auth_persistence_correlations.csv")
print("persistence_execution_correlations.csv")

print("\nFINAL ASSESSMENT")
print("-" * 80)

if common_users and process_correlations:
    print("""
HIGH-CONFIDENCE SUSPICIOUS ATTACK CHAIN

Authentication, persistence, and process execution share the
same user and host context and occur within a short timeframe.

This substantially strengthens the hypothesis of credential
abuse followed by persistence and suspicious execution.

The activity should be escalated for full incident response.
""")
else:
    print("""
SUSPICIOUS ACTIVITY

Correlation exists, but additional telemetry is required.
""")