import pandas as pd

file = "hunt01_results/scored_authentication_logs.csv"

df = pd.read_csv(file)

df["timestamp"] = pd.to_datetime(df["timestamp"])

# Move the suspicious Alice events to the incident date: Aug 28
mask = (
    (df["user"] == "alice") &
    (df["src_ip"] == "10.10.20.15")
)

df.loc[mask, "timestamp"] = (
    df.loc[mask, "timestamp"]
    .apply(lambda x: x.replace(year=2026, month=8, day=28))
)

df.to_csv(file, index=False)

print("=" * 70)
print("HUNT #1 DATE ALIGNMENT")
print("=" * 70)

print("\nAlice suspicious events:")
print(
    df[mask][
        ["timestamp", "user", "src_ip", "dest_computer", "anomaly_score"]
    ]
    .sort_values("timestamp")
    .to_string(index=False)
)

print("\nSaved:", file)