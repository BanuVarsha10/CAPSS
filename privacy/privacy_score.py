import os
import csv
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

RESULTS_DIR = os.path.join(BASE_DIR, "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

REPORT_FILE = os.path.join(RESULTS_DIR, "privacy_report.txt")

# --------------------------------------------------
# Maximum Possible Exposure
# --------------------------------------------------

MAX_WEIGHTS = {
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
# Overall Risk Score Weights
# --------------------------------------------------
# Overall_Risk_Score (0-100) = Repeated Registrations
#                             + Failed Registrations
#                             + Metadata Exposure
#                             + Attack Indicators
#
# NOTE: This is the full combined risk picture (kept exactly as
# before, only renamed from "Risk_Score" to "Overall_Risk_Score").
# Repeated/Failed/Attack Indicators conceptually belong to Threat
# Detection, but per your call they stay here rather than being
# removed - Privacy_Risk_Score (below) is the separate, pure
# exposure-only score requested on top of this.
#
# These weights are a documented design choice (they sum to 100)
# so the final Overall_Risk_Score stays on a 0-100 scale like the
# existing Privacy/Exposure/Privacy_Risk_Score.

RISK_WEIGHTS = {
    "Repeated_Registrations": 30,
    "Failed_Registrations": 25,
    "Metadata_Exposure": 30,
    "Attack_Indicators": 15
}

# Registration/auth outcome values used consistently with the
# rest of the pipeline (correlation_analyzer.py compares these
# as uppercase, e.g. "SUCCESS" / "FAILED").
SUCCESS_KEYWORDS = {"SUCCESS"}

# Placeholder values used by the anonymizer for DNN / S_NSSAI.
# Anything that doesn't match one of these is treated as a real,
# specific value (and therefore more identifying).
DNN_PLACEHOLDER_VALUES = {"DEFAULT_DNN"}
NSSAI_PLACEHOLDER_VALUES = {"DEFAULT_SLICE"}

# --------------------------------------------------
# Safe field access (boundary condition: short/malformed rows)
# --------------------------------------------------
# csv.DictReader fills missing trailing columns with None rather
# than "". Every call site below does field(row, col).strip()-
# equivalent work, so this keeps an "always a stripped string"
# contract without changing any scoring logic.

def field(row, key):
    value = row.get(key)
    return value.strip() if value else ""

# --------------------------------------------------
# Exposure Calculation Functions
# --------------------------------------------------

def ue_id_exposure(value):
    # Case-insensitive so real IDs / pseudonyms are recognized
    # regardless of how the source system cased them
    # (e.g. "imsi-...", "IMSI-...", "UE_001", "ue_001").
    lowered = value.lower()
    if value == "":
        return 0
    elif lowered.startswith("imsi"):
        return 30          # Original IMSI
    elif lowered.startswith("ue_"):
        return 5           # Pseudonym
    else:
        return 10

def suci_exposure(value):
    lowered = value.lower()
    if value == "":
        return 0
    elif lowered.startswith("suci_"):
        return 5           # Anonymized label, e.g. SUCI_001 / suci_001
    elif lowered.startswith("suci"):
        return 20          # Real SUCI, e.g. suci-0-999-... / SUCI-0-999-...
    else:
        return 10

def gnb_exposure(value):
    if value == "":
        return 0
    elif "xxx" in value.lower():
        return 3           # Masked IP
    else:
        return 15          # Real IP

def timestamp_exposure(value):
    if value == "":
        return 0
    elif value.lower().startswith("t+"):
        return 2           # Relative timestamp
    else:
        return 5           # Exact timestamp

def generic_exposure(value, weight):
    if value == "":
        return 0
    return weight

def dnn_exposure(value):
    # generic_exposure() only checks empty-vs-non-empty, so a
    # placeholder like "DEFAULT_DNN" would score identically to a
    # real APN name like "internet". Placeholders now score low
    # (same weight as any other anonymized pseudonym-style field)
    # and any other value is treated as real/identifying.
    if value == "":
        return 0
    elif value.upper() in DNN_PLACEHOLDER_VALUES:
        return 3
    else:
        return 10

def nssai_exposure(value):
    # Same fix as dnn_exposure(), for S_NSSAI.
    if value == "":
        return 0
    elif value.upper() in NSSAI_PLACEHOLDER_VALUES:
        return 3
    else:
        return 10

# --------------------------------------------------
# Overall Risk Score - Component Functions
# --------------------------------------------------

def repeated_registrations_component(ue_id, ue_id_counts):
    # Same UE reappearing across the dataset is the "repeated
    # registrations" signal. Each repeat beyond the first adds
    # points, capped at the weight ceiling.
    count = ue_id_counts.get(ue_id, 0)
    if count <= 1:
        return 0
    return min(RISK_WEIGHTS["Repeated_Registrations"], (count - 1) * 6)

def failed_registrations_component(registration_status, authentication_result):

    reg = registration_status.strip().upper()
    auth = authentication_result.strip().upper()

    # Empty registration = failure
    reg_failed = (reg == "") or (reg not in SUCCESS_KEYWORDS)

    # Empty authentication = NOT a failure
    auth_failed = (auth != "") and (auth not in SUCCESS_KEYWORDS)

    if reg_failed or auth_failed:
        return RISK_WEIGHTS["Failed_Registrations"]

    return 0

def metadata_exposure_component(exposure_value):
    # Reuses the existing 0-100 Exposure score, scaled down to
    # its share of the overall Risk Score.
    return round(exposure_value * (RISK_WEIGHTS["Metadata_Exposure"] / 100), 2)

def attack_indicators_component(ue_id, ue_id_counts, registration_status, authentication_result):
    # A simple proxy for "attack indicators": repetition alone
    # is a privacy risk, but repetition COMBINED with a failure
    # is treated as a stronger signal of active probing/misuse.
    count = ue_id_counts.get(ue_id, 0)
    reg = registration_status.strip().upper()
    auth = authentication_result.strip().upper()

    # Empty registration = failure
    reg_failed = (reg == "") or (reg not in SUCCESS_KEYWORDS)

    # Empty authentication = not a failure
    auth_failed = (auth != "") and (auth not in SUCCESS_KEYWORDS)

    has_failure = reg_failed or auth_failed

    if not has_failure:
        return 0
    if count >= 5:
        return RISK_WEIGHTS["Attack_Indicators"]
    elif count >= 3:
        return round(RISK_WEIGHTS["Attack_Indicators"] * 0.5, 2)
    return 0

def risk_level_from_score(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    else:
        return "LOW"

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------

scores = []

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)
    rows = list(reader)

# UE_ID repeat counts across the whole dataset - needed for the
# "Repeated Registrations" and "Attack Indicators" components of
# Overall_Risk_Score.
ue_id_counts = Counter(field(row, "UE_ID") for row in rows)

for row in rows:

    exposure = 0

    exposure += ue_id_exposure(field(row, "UE_ID"))
    exposure += suci_exposure(field(row, "SUCI"))
    exposure += gnb_exposure(field(row, "gNB_IP"))
    exposure += timestamp_exposure(field(row, "Timestamp"))

    exposure += dnn_exposure(field(row, "DNN"))
    exposure += nssai_exposure(field(row, "S_NSSAI"))
    exposure += generic_exposure(field(row, "Authentication_Result"), 5)
    exposure += generic_exposure(field(row, "Registration_Status"), 5)

    privacy_score = max(0, 100 - exposure)

    # ----------------------------------------------
    # Privacy_Risk_Score - exposure only
    # ----------------------------------------------
    # Per the requested split: this is the pure "how identifying
    # is this record's metadata" score, with no behavioural
    # signals (repeats/failures/attack indicators) mixed in.
    # Those live in Overall_Risk_Score instead.

    privacy_risk_score = min(100, exposure)
    privacy_risk_level = risk_level_from_score(privacy_risk_score)

    # ----------------------------------------------
    # Overall_Risk_Score (renamed from Risk_Score - same
    # calculation as before: repeats + failures + metadata
    # exposure + attack indicators)
    # ----------------------------------------------

    ue_id_stripped = field(row, "UE_ID")

    overall_risk_score = 0
    overall_risk_score += repeated_registrations_component(ue_id_stripped, ue_id_counts)
    overall_risk_score += failed_registrations_component(
        field(row, "Registration_Status"),
        field(row, "Authentication_Result")
    )
    overall_risk_score += metadata_exposure_component(exposure)
    overall_risk_score += attack_indicators_component(
        ue_id_stripped,
        ue_id_counts,
        field(row, "Registration_Status"),
        field(row, "Authentication_Result")
    )

    overall_risk_score = min(100, round(overall_risk_score, 2))
    overall_risk_level = risk_level_from_score(overall_risk_score)

    scores.append({
        "Timestamp": row.get("Timestamp", ""),
        "UE_ID": row.get("UE_ID", ""),
        "Exposure": exposure,
        "Privacy": privacy_score,
        "Privacy_Risk_Score": privacy_risk_score,
        "Privacy_Risk_Level": privacy_risk_level,
        "Overall_Risk_Score": overall_risk_score,
        "Overall_Risk_Level": overall_risk_level
    })

# --------------------------------------------------
# Statistics
# --------------------------------------------------

total_records = len(scores)

average_privacy = (
    sum(r["Privacy"] for r in scores)/total_records
    if total_records else 0
)

highest_exposure = max((r["Exposure"] for r in scores), default=0)
lowest_exposure = min((r["Exposure"] for r in scores), default=0)

average_privacy_risk_score = (
    sum(r["Privacy_Risk_Score"] for r in scores)/total_records
    if total_records else 0
)

highest_privacy_risk_score = max((r["Privacy_Risk_Score"] for r in scores), default=0)
lowest_privacy_risk_score = min((r["Privacy_Risk_Score"] for r in scores), default=0)

average_overall_risk_score = (
    sum(r["Overall_Risk_Score"] for r in scores)/total_records
    if total_records else 0
)

highest_overall_risk_score = max(r["Overall_Risk_Score"] for r in scores) if scores else 0
lowest_overall_risk_score = min(r["Overall_Risk_Score"] for r in scores) if scores else 0

# --------------------------------------------------
# Console Report
# --------------------------------------------------

print("\n========== Privacy Report ==========\n")

print(f"Total Records          : {total_records}")
print(f"Average Privacy Score  : {average_privacy:.2f}")
print(f"Highest Exposure Score : {highest_exposure}")
print(f"Lowest Exposure Score  : {lowest_exposure}")

print("\n========== Privacy Risk Score (Exposure Only) ==========\n")

print(f"Average Privacy Risk Score : {average_privacy_risk_score:.2f}")
print(f"Highest Privacy Risk Score : {highest_privacy_risk_score}")
print(f"Lowest Privacy Risk Score  : {lowest_privacy_risk_score}")

print("\n========== Overall Risk Score ==========\n")

print(f"Average Overall Risk Score : {average_overall_risk_score:.2f}")
print(f"Highest Overall Risk Score : {highest_overall_risk_score}")
print(f"Lowest Overall Risk Score  : {lowest_overall_risk_score}")

print("\nIndividual Records\n")

for i,record in enumerate(scores,1):

    print(
        f"Record {i}: "
        f"Exposure={record['Exposure']} "
        f"Privacy={record['Privacy']} "
        f"Privacy_Risk_Score={record['Privacy_Risk_Score']} "
        f"Privacy_Risk_Level={record['Privacy_Risk_Level']} "
        f"Overall_Risk_Score={record['Overall_Risk_Score']} "
        f"Overall_Risk_Level={record['Overall_Risk_Level']}"
    )

# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(REPORT_FILE,"w",encoding="utf-8") as report:

    report.write("========== Privacy Report ==========\n\n")

    report.write(f"Total Records          : {total_records}\n")
    report.write(f"Average Privacy Score  : {average_privacy:.2f}\n")
    report.write(f"Highest Exposure Score : {highest_exposure}\n")
    report.write(f"Lowest Exposure Score  : {lowest_exposure}\n\n")

    report.write("========== Privacy Risk Score (Exposure Only) ==========\n\n")

    report.write(f"Average Privacy Risk Score : {average_privacy_risk_score:.2f}\n")
    report.write(f"Highest Privacy Risk Score : {highest_privacy_risk_score}\n")
    report.write(f"Lowest Privacy Risk Score  : {lowest_privacy_risk_score}\n\n")

    report.write("========== Overall Risk Score ==========\n\n")

    report.write(f"Average Overall Risk Score : {average_overall_risk_score:.2f}\n")
    report.write(f"Highest Overall Risk Score : {highest_overall_risk_score}\n")
    report.write(f"Lowest Overall Risk Score  : {lowest_overall_risk_score}\n\n")

    report.write("Individual Records\n\n")

    for i,record in enumerate(scores,1):

        report.write(
            f"Record {i}\n"
            f"Timestamp          : {record['Timestamp']}\n"
            f"UE_ID              : {record['UE_ID']}\n"
            f"Exposure           : {record['Exposure']}\n"
            f"Privacy            : {record['Privacy']}\n"
            f"Privacy_Risk_Score : {record['Privacy_Risk_Score']}\n"
            f"Privacy_Risk_Level : {record['Privacy_Risk_Level']}\n"
            f"Overall_Risk_Score : {record['Overall_Risk_Score']}\n"
            f"Overall_Risk_Level : {record['Overall_Risk_Level']}\n\n"
        )

print("\nReport saved successfully!")
print(REPORT_FILE)