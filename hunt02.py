import pandas as pd


# ============================================================
# HUNT #2 — PERSISTENCE DETECTION
# ============================================================

df = pd.read_csv("persistence_logs.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hour"] = df["timestamp"].dt.hour


print("=" * 70)
print("HUNT #2 — PERSISTENCE DETECTION")
print("=" * 70)

print(f"\nTotal persistence events: {len(df)}")


# ============================================================
# SIGNAL 1 — OFF-HOURS PERSISTENCE
# ============================================================

off_hours = df[
    (df["hour"] < 7) |
    (df["hour"] > 20)
]

print("\n" + "=" * 70)
print("SIGNAL 1 — OFF-HOURS PERSISTENCE")
print("=" * 70)

print(f"\nOff-hours events: {len(off_hours)}")

if len(off_hours) > 0:
    print(
        off_hours[
            [
                "timestamp",
                "host",
                "user",
                "mechanism",
                "name"
            ]
        ].to_string(index=False)
    )


# ============================================================
# SIGNAL 2 — SUSPICIOUS COMMANDS
# ============================================================

suspicious_keywords = [
    "powershell",
    "-enc",
    "executionpolicy bypass",
    "-w hidden",
    "users\\public",
    "temp\\",
    "appdata\\",
]


def suspicious_command(command):

    command = str(command).lower()

    for keyword in suspicious_keywords:

        if keyword in command:
            return True

    return False


df["suspicious_command"] = (
    df["command"]
    .apply(suspicious_command)
)


print("\n" + "=" * 70)
print("SIGNAL 2 — SUSPICIOUS COMMANDS")
print("=" * 70)

suspicious = df[
    df["suspicious_command"]
]

print(
    suspicious[
        [
            "timestamp",
            "host",
            "user",
            "mechanism",
            "name",
            "command"
        ]
    ].to_string(index=False)
)


# ============================================================
# SIGNAL 3 — MULTIPLE PERSISTENCE MECHANISMS
# ============================================================

print("\n" + "=" * 70)
print("SIGNAL 3 — MULTIPLE PERSISTENCE MECHANISMS")
print("=" * 70)


mechanism_counts = (
    df.groupby(
        ["host", "user"]
    )["mechanism"]
    .nunique()
    .sort_values(
        ascending=False
    )
)

print(
    mechanism_counts.to_string()
)


# ============================================================
# SIGNAL 4 — RAPID PERSISTENCE CREATION
# ============================================================

print("\n" + "=" * 70)
print("SIGNAL 4 — RAPID PERSISTENCE CREATION")
print("=" * 70)


df = df.sort_values("timestamp")

rapid_events = []


for host in df["host"].unique():

    host_events = df[
        df["host"] == host
    ].sort_values("timestamp")

    for i in range(len(host_events)):

        start = host_events.iloc[i]["timestamp"]

        end = (
            start +
            pd.Timedelta(minutes=10)
        )

        window = host_events[
            (host_events["timestamp"] >= start) &
            (host_events["timestamp"] <= end)
        ]

        mechanisms = (
            window["mechanism"]
            .nunique()
        )

        if mechanisms >= 3:

            rapid_events.append({
                "host": host,
                "user": window["user"].iloc[0],
                "start": start,
                "events": len(window),
                "mechanisms": mechanisms
            })


rapid = pd.DataFrame(
    rapid_events
)


if len(rapid) > 0:

    print(
        rapid.drop_duplicates()
        .to_string(index=False)
    )

else:

    print(
        "No rapid multi-mechanism persistence detected."
    )


# ============================================================
# COMBINED INVESTIGATION
# ============================================================

print("\n" + "=" * 70)
print("COMBINED INVESTIGATION")
print("=" * 70)


combined = df[
    (
        df["suspicious_command"]
    )
    |
    (
        df["timestamp"].dt.hour < 7
    )
]


print(
    combined[
        [
            "timestamp",
            "host",
            "user",
            "mechanism",
            "name",
            "command"
        ]
    ].to_string(index=False)
)


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("HUNT #2 SUMMARY")
print("=" * 70)

print(f"""
Total events:              {len(df)}
Off-hours events:          {len(off_hours)}
Suspicious commands:       {len(suspicious)}
Hosts/users with multiple
persistence mechanisms:    {len(mechanism_counts)}
Rapid persistence bursts:  {len(rapid)}
""")