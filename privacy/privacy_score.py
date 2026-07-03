import os
import csv

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_FILE = os.path.join(BASE_DIR, "..", "datasets", "registration_dataset.csv")

RESULTS_DIR = os.path.join(BASE_DIR, "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

REPORT_FILE = os.path.join(RESULTS_DIR, "privacy_report.txt")

# --------------------------------------------------
# Privacy Weights
# --------------------------------------------------

WEIGHTS = {
    "UE_ID": 30,
    "SUCI": 20,
    "gNB_IP": 15,
    "DNN": 10,
    "S_NSSAI": 10,
    "Timestamp": 5,
    "Authentication_Result": 5,
    "Registration_Status": 5
}

# --------------------------------------------------
# Variables
# --------------------------------------------------

scores = []

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        exposure = 0

        for field, weight in WEIGHTS.items():

            if row[field].strip() != "":
                exposure += weight

        privacy_score = max(0, 100 - exposure)

        scores.append({
            "Timestamp": row["Timestamp"],
            "UE_ID": row["UE_ID"],
            "Exposure": exposure,
            "Privacy": privacy_score
        })

# --------------------------------------------------
# Statistics
# --------------------------------------------------

total_records = len(scores)

average_privacy = (
    sum(record["Privacy"] for record in scores) / total_records
    if total_records > 0 else 0
)

highest_exposure = (
    max(record["Exposure"] for record in scores)
    if total_records > 0 else 0
)

lowest_exposure = (
    min(record["Exposure"] for record in scores)
    if total_records > 0 else 0
)

# --------------------------------------------------
# Display
# --------------------------------------------------

print("\n========== Privacy Report ==========\n")

print(f"Total Records          : {total_records}")
print(f"Average Privacy Score  : {average_privacy:.2f}")
print(f"Highest Exposure Score : {highest_exposure}")
print(f"Lowest Exposure Score  : {lowest_exposure}")

print("\nIndividual Records\n")

for i, record in enumerate(scores, start=1):
    print(
        f"Record {i}: "
        f"Exposure={record['Exposure']} "
        f"Privacy={record['Privacy']}"
    )

# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(REPORT_FILE, "w", encoding="utf-8") as report:

    report.write("========== Privacy Report ==========\n\n")

    report.write(f"Total Records          : {total_records}\n")
    report.write(f"Average Privacy Score  : {average_privacy:.2f}\n")
    report.write(f"Highest Exposure Score : {highest_exposure}\n")
    report.write(f"Lowest Exposure Score  : {lowest_exposure}\n\n")

    report.write("Individual Records\n\n")

    for i, record in enumerate(scores, start=1):

        report.write(
            f"Record {i}\n"
            f"Timestamp : {record['Timestamp']}\n"
            f"UE_ID     : {record['UE_ID']}\n"
            f"Exposure  : {record['Exposure']}\n"
            f"Privacy   : {record['Privacy']}\n\n"
        )

print("\nReport saved successfully!")
print(REPORT_FILE)