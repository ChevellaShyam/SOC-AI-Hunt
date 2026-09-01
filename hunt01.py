import pandas as pd

# ============================================================
# HUNT #1 — CREDENTIAL ABUSE DETECTION
# ============================================================

df = pd.read_csv("authentication_logs.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])

print("=" * 70)
print("HUNT #1 — CREDENTIAL ABUSE DETECTION")
print("=" * 70)

print(f"\nTotal events: {len(df)}")


# ============================================================
# SIGNAL 1 — SOURCE IP BEHAVIOR
# ============================================================

print("\n" + "=" * 70)
print("SIGNAL 1 — SOURCE IP BEHAVIOR")
print("=" * 70)

ip_stats = (
    df.groupby("src_ip")
    .agg(
        events=("src_ip", "size"),
        users=("user", "nunique"),
        computers=("dest_computer", "nunique")
    )
    .sort_values("events", ascending=False)
)

print(ip_stats.to_string())


# ============================================================
# SIGNAL 2 — OFF-HOURS ACTIVITY
# ============================================================

df["hour"] = df["timestamp"].dt.hour

off_hours = df[
    (df["hour"] < 7) |
    (df["hour"] > 20)
]

print("\n" + "=" * 70)
print("SIGNAL 2 — OFF-HOURS ACTIVITY")
print("=" * 70)

print(f"\nOff-hours events: {len(off_hours)}")

if len(off_hours) > 0:
    print(
        off_hours[
            [
                "timestamp",
                "user",
                "src_ip",
                "dest_computer"
            ]
        ].to_string(index=False)
    )


# ============================================================
# SIGNAL 3 — RAPID MULTI-COMPUTER ACCESS
# ============================================================

print("\n" + "=" * 70)
print("SIGNAL 3 — RAPID MULTI-COMPUTER ACCESS")
print("=" * 70)

# Sort chronologically
df = df.sort_values("timestamp")

suspicious_bursts = []

for user in df["user"].unique():

    user_events = df[df["user"] == user].sort_values("timestamp")

    for i in range(len(user_events)):

        window_start = user_events.iloc[i]["timestamp"]
        window_end = window_start + pd.Timedelta(minutes=2)

        window = user_events[
            (user_events["timestamp"] >= window_start) &
            (user_events["timestamp"] <= window_end)
        ]

        unique_computers = window["dest_computer"].nunique()

        if unique_computers >= 4:

            suspicious_bursts.append({
                "user": user,
                "start": window_start,
                "end": window_end,
                "events": len(window),
                "unique_computers": unique_computers,
                "source_ips": ", ".join(
                    window["src_ip"].unique()
                )
            })

bursts = pd.DataFrame(suspicious_bursts)

if len(bursts) > 0:

    print(
        bursts[
            [
                "user",
                "start",
                "events",
                "unique_computers",
                "source_ips"
            ]
        ].drop_duplicates().to_string(index=False)
    )

else:
    print("No rapid multi-computer activity detected.")


# ============================================================
# COMBINED INVESTIGATION
# ============================================================

print("\n" + "=" * 70)
print("COMBINED INVESTIGATION")
print("=" * 70)

# Find events that are both:
# - off-hours
# - from a relatively uncommon source IP

ip_frequency = df["src_ip"].value_counts()

rare_ips = ip_frequency[
    ip_frequency < 50
].index

combined = df[
    (
        (df["hour"] < 7) |
        (df["hour"] > 20)
    )
    &
    (
        df["src_ip"].isin(rare_ips)
    )
]

print("\nPotentially interesting events:")

print(
    combined[
        [
            "timestamp",
            "user",
            "src_ip",
            "dest_computer",
            "logon_type"
        ]
    ].to_string(index=False)
)


# ============================================================
# SUMMARY FOR AI
# ============================================================

print("\n" + "=" * 70)
print("SUMMARY FOR AI INVESTIGATION")
print("=" * 70)

summary = {
    "total_events": len(df),
    "off_hours_events": len(off_hours),
    "rare_source_ips": list(rare_ips),
    "interesting_events": len(combined)
}

print(summary)