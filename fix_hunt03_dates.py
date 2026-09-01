import pandas as pd

file = "process_execution_logs.csv"

df = pd.read_csv(file)
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Move WS07/Alice suspicious process events to Aug 28
mask = (
    (df["host"] == "WS07") &
    (df["user"] == "alice")
)

df.loc[mask, "timestamp"] = df.loc[mask, "timestamp"].apply(
    lambda x: x.replace(year=2026, month=8, day=28)
)

df.to_csv(file, index=False)

print("=" * 70)
print("HUNT #3 DATE ALIGNMENT")
print("=" * 70)

print(
    df[mask][
        ["timestamp", "host", "user", "process", "anomaly_score"]
    ].sort_values("timestamp").to_string(index=False)
)

print("\nSaved:", file)