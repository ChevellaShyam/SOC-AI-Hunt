import pandas as pd

events = [
    {
        "timestamp": "2026-08-25 02:14:55",
        "host": "WS07",
        "user": "alice",
        "process": "powershell.exe",
        "command": "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\update.ps1",
        "parent_process": "taskeng.exe"
    },
    {
        "timestamp": "2026-08-25 02:16:05",
        "host": "WS07",
        "user": "alice",
        "process": "powershell.exe",
        "command": "powershell.exe -w hidden -enc SQBFAFgA...",
        "parent_process": "explorer.exe"
    },
    {
        "timestamp": "2026-08-25 02:17:32",
        "host": "WS07",
        "user": "alice",
        "process": "svchost.exe",
        "command": "C:\\Users\\Public\\svchost.exe",
        "parent_process": "services.exe"
    },
    {
        "timestamp": "2026-08-25 02:19:47",
        "host": "WS07",
        "user": "alice",
        "process": "chrome_update.exe",
        "command": "C:\\Users\\Public\\chrome_update.exe",
        "parent_process": "taskeng.exe"
    },

    # Benign baseline
    {
        "timestamp": "2026-08-25 09:12:15",
        "host": "WS01",
        "user": "david",
        "process": "svchost.exe",
        "command": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        "parent_process": "services.exe"
    },
    {
        "timestamp": "2026-08-25 10:04:38",
        "host": "WS03",
        "user": "bob",
        "process": "MsMpEng.exe",
        "command": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
        "parent_process": "services.exe"
    },
    {
        "timestamp": "2026-08-25 10:21:46",
        "host": "WS04",
        "user": "charlie",
        "process": "backup.exe",
        "command": "C:\\Program Files\\Backup\\backup.exe",
        "parent_process": "services.exe"
    }
]

df = pd.DataFrame(events)

df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hour"] = df["timestamp"].dt.hour

df["off_hours"] = (
    (df["hour"] < 6) |
    (df["hour"] >= 22)
)

df["powershell"] = df["process"].str.lower().eq("powershell.exe")

df["encoded"] = df["command"].str.contains(
    "-enc",
    case=False,
    na=False
)

df["bypass"] = df["command"].str.contains(
    "ExecutionPolicy Bypass",
    case=False,
    na=False
)

df["hidden"] = df["command"].str.contains(
    "-w hidden",
    case=False,
    na=False
)

df["suspicious_path"] = df["command"].str.contains(
    r"C:\\Users\\Public\\",
    case=False,
    regex=True,
    na=False
)

df["suspicious_process"] = (
    df["powershell"] |
    df["encoded"] |
    df["bypass"] |
    df["hidden"] |
    df["suspicious_path"]
)

df["anomaly_score"] = 0

df.loc[df["off_hours"], "anomaly_score"] += 20
df.loc[df["powershell"], "anomaly_score"] += 20
df.loc[df["encoded"], "anomaly_score"] += 25
df.loc[df["bypass"], "anomaly_score"] += 20
df.loc[df["hidden"], "anomaly_score"] += 15
df.loc[df["suspicious_path"], "anomaly_score"] += 25

df["anomaly_score"] = df["anomaly_score"].clip(upper=100)

df["risk_level"] = pd.cut(
    df["anomaly_score"],
    bins=[-1, 29, 69, 100],
    labels=["LOW", "MEDIUM", "HIGH"]
)

df.to_csv("process_execution_logs.csv", index=False)

print("=" * 80)
print("HUNT #3 — PROCESS EXECUTION DATASET")
print("=" * 80)
print()
print(df.to_string(index=False))
print()
print("Saved: process_execution_logs.csv")