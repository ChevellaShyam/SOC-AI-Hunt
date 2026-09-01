import pandas as pd

events = [
    {
        "timestamp": "2026-08-25 02:14:51",
        "host": "WS07",
        "user": "alice",
        "process": "powershell.exe",
        "command": "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\update.ps1",
        "parent_process": "taskeng.exe",
        "execution_type": "Scheduled Task",
    },
    {
        "timestamp": "2026-08-25 02:16:02",
        "host": "WS07",
        "user": "alice",
        "process": "powershell.exe",
        "command": "powershell.exe -w hidden -enc SQBFAFgA...",
        "parent_process": "explorer.exe",
        "execution_type": "Registry Run Key",
    },
    {
        "timestamp": "2026-08-25 02:17:29",
        "host": "WS07",
        "user": "alice",
        "process": "svchost.exe",
        "command": "C:\\Users\\Public\\svchost.exe",
        "parent_process": "services.exe",
        "execution_type": "Service",
    },
    {
        "timestamp": "2026-08-25 02:19:44",
        "host": "WS07",
        "user": "alice",
        "process": "chrome_update.exe",
        "command": "C:\\Users\\Public\\chrome_update.exe",
        "parent_process": "taskeng.exe",
        "execution_type": "Scheduled Task",
    },

    # Benign baseline events
    {
        "timestamp": "2026-08-25 09:12:10",
        "host": "WS01",
        "user": "david",
        "process": "svchost.exe",
        "command": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        "parent_process": "services.exe",
        "execution_type": "Scheduled Task",
    },
    {
        "timestamp": "2026-08-25 11:15:03",
        "host": "WS05",
        "user": "admin",
        "process": "spoolsv.exe",
        "command": "C:\\Windows\\System32\\spoolsv.exe",
        "parent_process": "services.exe",
        "execution_type": "Service",
    },
    {
        "timestamp": "2026-08-25 10:21:41",
        "host": "WS04",
        "user": "charlie",
        "process": "backup.exe",
        "command": "C:\\Program Files\\Backup\\backup.exe",
        "parent_process": "services.exe",
        "execution_type": "Scheduled Task",
    },
    {
        "timestamp": "2026-08-25 10:04:33",
        "host": "WS03",
        "user": "bob",
        "process": "MsMpEng.exe",
        "command": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
        "parent_process": "services.exe",
        "execution_type": "Service",
    },
]

df = pd.DataFrame(events)

df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hour"] = df["timestamp"].dt.hour

df["off_hours"] = (
    (df["hour"] < 6) |
    (df["hour"] >= 22)
)

df["suspicious_powershell"] = (
    df["process"].str.lower().eq("powershell.exe")
    & (
        df["command"].str.contains("ExecutionPolicy Bypass", case=False, na=False)
        | df["command"].str.contains("-enc", case=False, na=False)
        | df["command"].str.contains("-w hidden", case=False, na=False)
    )
)

df["suspicious_path"] = df["command"].str.contains(
    r"C:\\Users\\Public\\",
    case=False,
    regex=True,
    na=False
)

df["encoded_command"] = df["command"].str.contains(
    "-enc",
    case=False,
    na=False
)

df["non_standard_location"] = df["suspicious_path"]

df["anomaly_score"] = 0

df.loc[df["off_hours"], "anomaly_score"] += 20
df.loc[df["suspicious_powershell"], "anomaly_score"] += 30
df.loc[df["suspicious_path"], "anomaly_score"] += 25
df.loc[df["encoded_command"], "anomaly_score"] += 25

df["anomaly_score"] = df["anomaly_score"].clip(upper=100)

df["risk_level"] = pd.cut(
    df["anomaly_score"],
    bins=[-1, 29, 69, 100],
    labels=["LOW", "MEDIUM", "HIGH"]
)

df.to_csv("execution_logs.csv", index=False)

print("=" * 80)
print("EXECUTION DATASET CREATED")
print("=" * 80)
print()
print(df.to_string(index=False))
print()
print("Saved: execution_logs.csv")