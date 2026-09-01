import pandas as pd


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv("persistence_logs.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hour"] = df["timestamp"].dt.hour


# ============================================================
# SIGNAL 1 — OFF-HOURS
# ============================================================

df["off_hours"] = (
    (df["hour"] < 7) |
    (df["hour"] > 20)
)


# ============================================================
# SIGNAL 2 — SUSPICIOUS POWERSHELL
# ============================================================

powershell_keywords = [
    "powershell",
    "executionpolicy bypass",
    "-enc",
    "-w hidden"
]


def contains_suspicious_powershell(command):

    command = str(command).lower()

    return (
        "powershell" in command
        and any(
            keyword in command
            for keyword in powershell_keywords
        )
    )


df["suspicious_powershell"] = (
    df["command"]
    .apply(contains_suspicious_powershell)
)


# ============================================================
# SIGNAL 3 — SUSPICIOUS FILE LOCATION
# ============================================================

def suspicious_path(command):

    command = str(command).lower()

    suspicious_paths = [
        "\\users\\public\\",
        "\\temp\\",
        "\\appdata\\"
    ]

    return any(
        path in command
        for path in suspicious_paths
    )


df["suspicious_path"] = (
    df["command"]
    .apply(suspicious_path)
)


# ============================================================
# SIGNAL 4 — MULTIPLE MECHANISMS
# ============================================================

mechanism_counts = (
    df.groupby(
        ["host", "user"]
    )["mechanism"]
    .nunique()
)

df["mechanism_count"] = [
    mechanism_counts.get(
        (host, user),
        0
    )
    for host, user in zip(
        df["host"],
        df["user"]
    )
]

df["multiple_mechanisms"] = (
    df["mechanism_count"] >= 3
)


# ============================================================
# SIGNAL 5 — RAPID PERSISTENCE
# ============================================================

df["rapid_persistence"] = False

for host in df["host"].unique():

    host_df = df[
        df["host"] == host
    ].sort_values("timestamp")

    for i in range(len(host_df)):

        start = host_df.iloc[i]["timestamp"]

        end = (
            start +
            pd.Timedelta(minutes=10)
        )

        window = host_df[
            (host_df["timestamp"] >= start) &
            (host_df["timestamp"] <= end)
        ]

        if window["mechanism"].nunique() >= 3:

            df.loc[
                window.index,
                "rapid_persistence"
            ] = True


# ============================================================
# SCORE
# ============================================================

df["anomaly_score"] = 0

df.loc[
    df["off_hours"],
    "anomaly_score"
] += 20

df.loc[
    df["suspicious_powershell"],
    "anomaly_score"
] += 25

df.loc[
    df["suspicious_path"],
    "anomaly_score"
] += 20

df.loc[
    df["multiple_mechanisms"],
    "anomaly_score"
] += 20

df.loc[
    df["rapid_persistence"],
    "anomaly_score"
] += 15


# ============================================================
# RISK LEVEL
# ============================================================

def risk(score):

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


df["risk_level"] = (
    df["anomaly_score"]
    .apply(risk)
)


# ============================================================
# DISPLAY
# ============================================================

print("=" * 80)
print("HUNT #2 — PERSISTENCE ANOMALY SCORING")
print("=" * 80)

columns = [
    "timestamp",
    "host",
    "user",
    "mechanism",
    "name",
    "anomaly_score",
    "risk_level"
]

print(
    df.sort_values(
        "anomaly_score",
        ascending=False
    )[columns].to_string(
        index=False
    )
)


# ============================================================
# SAVE
# ============================================================

df.to_csv(
    "persistence_scored.csv",
    index=False
)

print("\nSaved:")
print("persistence_scored.csv")