import pandas as pd


data = [
    {
        "timestamp": "2026-08-25 09:12:10",
        "host": "WS01",
        "user": "david",
        "mechanism": "Scheduled Task",
        "name": "WindowsUpdateCheck",
        "command": "C:\\Windows\\System32\\svchost.exe -k netsvcs"
    },
    {
        "timestamp": "2026-08-25 09:30:22",
        "host": "WS02",
        "user": "alice",
        "mechanism": "Registry Run Key",
        "name": "OneDrive",
        "command": "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\""
    },
    {
        "timestamp": "2026-08-25 10:04:33",
        "host": "WS03",
        "user": "bob",
        "mechanism": "Service",
        "name": "Windows Defender Service",
        "command": "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
    },
    {
        "timestamp": "2026-08-25 10:21:41",
        "host": "WS04",
        "user": "charlie",
        "mechanism": "Scheduled Task",
        "name": "BackupTask",
        "command": "C:\\Program Files\\Backup\\backup.exe"
    },
    {
        "timestamp": "2026-08-25 11:15:03",
        "host": "WS05",
        "user": "admin",
        "mechanism": "Service",
        "name": "Print Spooler",
        "command": "C:\\Windows\\System32\\spoolsv.exe"
    },

    # Suspicious entries
    {
        "timestamp": "2026-08-25 02:14:51",
        "host": "WS07",
        "user": "alice",
        "mechanism": "Scheduled Task",
        "name": "WindowsSecurityUpdate",
        "command": "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\update.ps1"
    },
    {
        "timestamp": "2026-08-25 02:16:02",
        "host": "WS07",
        "user": "alice",
        "mechanism": "Registry Run Key",
        "name": "WindowsUpdate",
        "command": "powershell.exe -w hidden -enc SQBFAFgA..."
    },
    {
        "timestamp": "2026-08-25 02:17:29",
        "host": "WS07",
        "user": "alice",
        "mechanism": "Service",
        "name": "WindowsTelemetry",
        "command": "C:\\Users\\Public\\svchost.exe"
    },
    {
        "timestamp": "2026-08-25 02:19:44",
        "host": "WS07",
        "user": "alice",
        "mechanism": "Scheduled Task",
        "name": "ChromeUpdate",
        "command": "C:\\Users\\Public\\chrome_update.exe"
    }
]


df = pd.DataFrame(data)

df.to_csv(
    "persistence_logs.csv",
    index=False
)

print("=" * 70)
print("PERSISTENCE DATASET CREATED")
print("=" * 70)

print(f"\nTotal persistence events: {len(df)}")

print("\nSaved:")
print("persistence_logs.csv")