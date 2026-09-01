import pandas as pd


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv("authentication_logs.csv")

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
# SIGNAL 2 — RARE SOURCE IP
# ============================================================

ip_counts = df["src_ip"].value_counts()

df["rare_ip"] = (
    df["src_ip"].map(ip_counts) < 50
)


# ============================================================
# SIGNAL 3 — UNUSUAL USER/IP COMBINATION
# ============================================================

user_ip_counts = (
    df.groupby(["user", "src_ip"])
    .size()
)

df["user_ip_frequency"] = [
    user_ip_counts.get(
        (user, ip),
        0
    )
    for user, ip in zip(
        df["user"],
        df["src_ip"]
    )
]

df["unusual_user_ip"] = (
    df["user_ip_frequency"] < 30
)


# ============================================================
# SIGNAL 4 — RAPID MULTI-COMPUTER ACCESS
# ============================================================

df = df.sort_values("timestamp")

df["rapid_multi_system"] = False


for user in df["user"].unique():

    indices = df[
        df["user"] == user
    ].index.tolist()

    for i in range(len(indices)):

        current_index = indices[i]

        start_time = df.loc[
            current_index,
            "timestamp"
        ]

        end_time = (
            start_time +
            pd.Timedelta(minutes=2)
        )

        window = df[
            (df["user"] == user) &
            (df["timestamp"] >= start_time) &
            (df["timestamp"] <= end_time)
        ]

        unique_systems = (
            window["dest_computer"]
            .nunique()
        )

        if unique_systems >= 4:

            df.loc[
                window.index,
                "rapid_multi_system"
            ] = True


# ============================================================
# CALCULATE SCORE
# ============================================================

df["anomaly_score"] = 0

df.loc[
    df["off_hours"],
    "anomaly_score"
] += 30

df.loc[
    df["rare_ip"],
    "anomaly_score"
] += 30

df.loc[
    df["unusual_user_ip"],
    "anomaly_score"
] += 20

df.loc[
    df["rapid_multi_system"],
    "anomaly_score"
] += 20


# ============================================================
# CLASSIFICATION
# ============================================================

def classify(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


df["risk_level"] = (
    df["anomaly_score"]
    .apply(classify)
)


# ============================================================
# DISPLAY TOP EVENTS
# ============================================================

print("=" * 80)
print("HUNT #1 — ANOMALY SCORING")
print("=" * 80)

top_events = (
    df.sort_values(
        "anomaly_score",
        ascending=False
    )
    .head(20)
)

columns = [
    "timestamp",
    "user",
    "src_ip",
    "dest_computer",
    "logon_type",
    "anomaly_score",
    "risk_level"
]

print(
    top_events[
        columns
    ].to_string(index=False)
)


# ============================================================
# SAVE RESULTS
# ============================================================

df.to_csv(
    "hunt01_results/scored_authentication_logs.csv",
    index=False
)

print("\nResults saved to:")
print(
    "hunt01_results/scored_authentication_logs.csv"
)