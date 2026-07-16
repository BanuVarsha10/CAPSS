import os
import csv

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_FILE = os.path.join(
    BASE_DIR,
    "..",
    "datasets",
    "registration_dataset20.csv"
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "..",
    "results"
)

os.makedirs(RESULTS_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(
    RESULTS_DIR,
    "registration_summary.txt"
)

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------

records = []

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        # ------------------------------------------
        # Treat blank authentication as Success
        # ------------------------------------------

        if row["Authentication_Result"].strip() == "":
            row["Authentication_Result"] = "Success"

        records.append(row)

# --------------------------------------------------
# Display
# --------------------------------------------------

print("\n========== Registration Summary ==========\n")

for index, record in enumerate(records, start=1):

    print(f"Registration #{index}")
    print("-" * 40)
    print(f"Timestamp            : {record['Timestamp']}")
    print(f"Event                : {record['Event']}")
    print(f"UE_ID                : {record['UE_ID']}")
    print(f"SUCI                 : {record['SUCI']}")
    print(f"Authentication       : {record['Authentication_Result']}")
    print(f"Registration Status  : {record['Registration_Status']}")
    print(f"gNB IP               : {record['gNB_IP']}")
    print(f"DNN                  : {record['DNN']}")
    print(f"S_NSSAI              : {record['S_NSSAI']}")
    print()

print("=" * 42)
print(f"Total Registrations : {len(records)}")

# --------------------------------------------------
# Save Summary
# --------------------------------------------------

with open(OUTPUT_FILE, "w", encoding="utf-8") as report:

    report.write("========== Registration Summary ==========\n\n")

    for index, record in enumerate(records, start=1):

        report.write(f"Registration #{index}\n")
        report.write("-" * 40 + "\n")
        report.write(f"Timestamp            : {record['Timestamp']}\n")
        report.write(f"Event                : {record['Event']}\n")
        report.write(f"UE_ID                : {record['UE_ID']}\n")
        report.write(f"SUCI                 : {record['SUCI']}\n")
        report.write(f"Authentication       : {record['Authentication_Result']}\n")
        report.write(f"Registration Status  : {record['Registration_Status']}\n")
        report.write(f"gNB IP               : {record['gNB_IP']}\n")
        report.write(f"DNN                  : {record['DNN']}\n")
        report.write(f"S_NSSAI              : {record['S_NSSAI']}\n\n")

    report.write("=" * 42 + "\n")
    report.write(f"Total Registrations : {len(records)}\n")

print("\nRegistration summary saved successfully!")
print(OUTPUT_FILE)