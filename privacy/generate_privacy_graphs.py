import os
import csv
import matplotlib.pyplot as plt
from collections import Counter

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

GRAPH_DIR = os.path.join(
    RESULTS_DIR,
    "graphs"
)

os.makedirs(GRAPH_DIR, exist_ok=True)

# --------------------------------------------------
# Registration/Auth Outcome Keywords
# --------------------------------------------------
# NOTE: kept in the same uppercase style as
# correlation_analyzer.py's FAILURE_KEYWORDS/SUCCESS_KEYWORDS,
# so this pipeline agrees on what "success" means everywhere.
# If correlation_analyzer.py's sets are ever shared as an
# importable module, swap this local definition for an import
# from there instead of keeping a second copy in sync by hand.

SUCCESS_KEYWORDS = {"SUCCESS"}

# --------------------------------------------------
# Exposure Calculation Functions
# --------------------------------------------------

def ue_id_exposure(value):
    if value == "":
        return 0
    elif value.startswith("imsi"):
        return 30          # Original IMSI
    elif value.startswith("UE_"):
        return 5           # Pseudonymized
    else:
        return 10


def suci_exposure(value):
    if value == "":
        return 0
    elif value.startswith("SUCI_"):
        return 5           # Pseudonymized
    elif value.startswith("suci"):
        return 20          # Original SUCI
    else:
        return 10


def gnb_exposure(value):
    if value == "":
        return 0
    elif "xxx" in value:
        return 3           # Masked IP
    else:
        return 15          # Original IP


def timestamp_exposure(value):
    if value == "":
        return 0
    elif value.startswith("T+"):
        return 2           # Relative Timestamp
    else:
        return 5           # Exact Timestamp


def generic_exposure(value, weight):
    if value == "":
        return 0
    return weight

# --------------------------------------------------
# Variables
# --------------------------------------------------

privacy_scores = []

exposure_scores = []

registration_status = []

authentication = []

ue_ids = []

suci_ids = []

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        exposure = 0

        exposure += ue_id_exposure(row["UE_ID"].strip())
        exposure += suci_exposure(row["SUCI"].strip())
        exposure += gnb_exposure(row["gNB_IP"].strip())
        exposure += timestamp_exposure(row["Timestamp"].strip())

        exposure += generic_exposure(row["DNN"].strip(), 10)
        exposure += generic_exposure(row["S_NSSAI"].strip(), 10)
        exposure += generic_exposure(row["Authentication_Result"].strip(), 5)
        exposure += generic_exposure(row["Registration_Status"].strip(), 5)

        privacy = max(0, 100 - exposure)

        exposure_scores.append(exposure)
        privacy_scores.append(privacy)

        registration_status.append(row["Registration_Status"])
        authentication.append(row["Authentication_Result"])

        if row["UE_ID"]:
            ue_ids.append(row["UE_ID"])

        if row["SUCI"]:
            suci_ids.append(row["SUCI"])

# --------------------------------------------------
# Graph 1
# Privacy Score Distribution
# --------------------------------------------------

plt.figure(figsize=(8,5))

plt.bar(
    range(1, len(privacy_scores)+1),
    privacy_scores
)

plt.title("Privacy Score Distribution")

plt.xlabel("Registration Record")

plt.ylabel("Privacy Score")

plt.ylim(0,100)

plt.tight_layout()

plt.savefig(
    os.path.join(
        GRAPH_DIR,
        "privacy_score_distribution.png"
    )
)

plt.close()

# --------------------------------------------------
# Graph 2
# Exposure Distribution
# --------------------------------------------------

plt.figure(figsize=(8,5))

plt.bar(
    range(1, len(exposure_scores)+1),
    exposure_scores
)

plt.title("Metadata Exposure Distribution")

plt.xlabel("Registration Record")

plt.ylabel("Exposure Score")

plt.ylim(0,100)

plt.tight_layout()

plt.savefig(
    os.path.join(
        GRAPH_DIR,
        "exposure_distribution.png"
    )
)

plt.close()

# --------------------------------------------------
# Graph 3
# Identifier Statistics
# --------------------------------------------------

unique_ue = len(set(ue_ids))

unique_suci = len(set(suci_ids))

repeated_ue = sum(
    1
    for count in Counter(ue_ids).values()
    if count > 1
)

repeated_suci = sum(
    1
    for count in Counter(suci_ids).values()
    if count > 1
)

labels = [
    "Unique UE",
    "Repeated UE",
    "Unique SUCI",
    "Repeated SUCI"
]

values = [
    unique_ue,
    repeated_ue,
    unique_suci,
    repeated_suci
]

plt.figure(figsize=(8,5))

plt.bar(labels, values)

plt.title("Identifier Statistics")

plt.ylabel("Count")

plt.tight_layout()

plt.savefig(
    os.path.join(
        GRAPH_DIR,
        "identifier_statistics.png"
    )
)

plt.close()

# --------------------------------------------------
# Graph 4
# Registration Statistics
# --------------------------------------------------

# NOTE: was previously registration_status.count("Success"),
# which is a case-sensitive exact match. If the CSV stores
# uppercase values ("SUCCESS"/"FAILED", as the rest of this
# pipeline assumes), that comparison never matched anything and
# this chart always showed 0% success regardless of the real
# data. Comparing case-insensitively against the shared keyword
# set fixes that.

success = sum(
    1
    for status in registration_status
    if status.strip().upper() in SUCCESS_KEYWORDS
)

failure = len(registration_status) - success

plt.figure(figsize=(6,6))

plt.pie(
    [success, failure],
    labels=["Success", "Failure"],
    autopct="%1.1f%%",
    startangle=90
)

plt.title("Registration Success Rate")

plt.tight_layout()

plt.savefig(
    os.path.join(
        GRAPH_DIR,
        "registration_statistics.png"
    )
)

plt.close()

# --------------------------------------------------
# Done
# --------------------------------------------------

print("\n===========================================")
print("Privacy Graphs Generated Successfully")
print("===========================================")

print(f"Output Directory : {GRAPH_DIR}")

print("\nGenerated Files")

print("------------------------------")

print("privacy_score_distribution.png")
print("exposure_distribution.png")
print("identifier_statistics.png")
print("registration_statistics.png")

print("------------------------------")