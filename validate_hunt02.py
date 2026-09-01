import os
import hashlib
import base64
import re

print("=" * 70)
print("HUNT #2 ARTIFACT VALIDATION")
print("=" * 70)

# --------------------------------------------------
# 1. Check suspicious files
# --------------------------------------------------

files = [
    r"C:\Users\Public\update.ps1",
    r"C:\Users\Public\chrome_update.exe",
    r"C:\Users\Public\svchost.exe"
]

print("\n[1] FILE VALIDATION")
print("-" * 70)

for path in files:
    print(f"\nFile: {path}")

    if os.path.exists(path):
        size = os.path.getsize(path)

        with open(path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()

        print("EXISTS: YES")
        print(f"Size: {size} bytes")
        print(f"SHA256: {sha256}")
    else:
        print("EXISTS: NO")


# --------------------------------------------------
# 2. Decode the known encoded PowerShell command
# --------------------------------------------------

print("\n\n[2] POWERSHELL ENCODED COMMAND")
print("-" * 70)

encoded = "SQBFAFgA"

try:
    decoded = base64.b64decode(encoded)
    print("Decoded bytes:", decoded)

    try:
        print("UTF-16 decoded:", decoded.decode("utf-16-le"))
    except:
        print("UTF-8 decoded:", decoded.decode("utf-8", errors="replace"))

except Exception as e:
    print("Decode error:", e)


# --------------------------------------------------
# 3. Check persistence artifact names
# --------------------------------------------------

print("\n\n[3] PERSISTENCE REVIEW")
print("-" * 70)

artifacts = {
    "Scheduled Task": "WindowsSecurityUpdate",
    "Scheduled Task": "ChromeUpdate",
    "Registry Run Key": "WindowsUpdate",
    "Service": "WindowsTelemetry"
}

for mechanism, name in artifacts.items():
    print(f"{mechanism}: {name}")

print("\nSuspicious characteristics:")
print("- Multiple persistence mechanisms")
print("- Off-hours activity")
print("- PowerShell encoded command")
print("- ExecutionPolicy Bypass")
print("- Hidden PowerShell window")
print("- Executables/scripts in C:\\Users\\Public")


# --------------------------------------------------
# 4. Final validation result
# --------------------------------------------------

print("\n\n[4] VALIDATION ASSESSMENT")
print("-" * 70)

print("""
STATUS: SUSPICIOUS

The available telemetry supports the persistence hypothesis,
but does not independently confirm malware execution.

Next investigation priority:
1. Obtain actual file contents.
2. Decode the complete PowerShell command.
3. Verify service configuration.
4. Check process creation telemetry.
5. Check network connections from WS07.
""")

print("=" * 70)
print("VALIDATION COMPLETE")
print("=" * 70)