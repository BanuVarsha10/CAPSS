import os
import csv
import re


# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


DATASET_DIR = os.path.join(
    BASE_DIR,
    "..",
    "datasets"
)


RESULTS_DIR = os.path.join(
    BASE_DIR,
    "..",
    "results"
)


os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)



ANON_DATASET = os.path.join(
    RESULTS_DIR,
    "anonymized_registration_dataset10.csv"
)



PRIVACY_REPORT = os.path.join(
    RESULTS_DIR,
    "privacy_report.txt"
)



CORRELATION_REPORT = os.path.join(
    RESULTS_DIR,
    "correlation_report.txt"
)



THREAT_REPORT = os.path.join(
    RESULTS_DIR,
    "privacy_threat_report.txt"
)



OUTPUT_FILE = os.path.join(
    RESULTS_DIR,
    "privacy_summary.txt"
)





# --------------------------------------------------
# Read Existing Reports
# --------------------------------------------------

def read_file(path):

    if os.path.exists(path):

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return file.read()

    return "Report not available."




privacy_report = read_file(
    PRIVACY_REPORT
)


correlation_report = read_file(
    CORRELATION_REPORT
)


threat_report = read_file(
    THREAT_REPORT
)





# --------------------------------------------------
# Extract Privacy Metrics
# --------------------------------------------------

def extract_value(text, keyword):

    pattern = keyword + r".*?:\s*(.*)"

    match = re.search(
        pattern,
        text
    )

    if match:

        return match.group(1).strip()

    return "Not available"





privacy_score = extract_value(
    privacy_report,
    "Average Privacy Score"
)


# NOTE: was previously extract_value(privacy_report, "Exposure Score"),
# which is a substring of BOTH "Highest Exposure Score" and
# "Lowest Exposure Score" - re.search silently grabbed whichever
# line came first (Highest), while the summary label below called
# it "Average Exposure Score". There is no "Average Exposure Score"
# line in privacy_report.txt, so the label was simply wrong about
# what the number represented. Targeting the exact label removes
# the ambiguity.
exposure_score = extract_value(
    privacy_report,
    "Highest Exposure Score"
)


# --------------------------------------------------
# Extract Privacy Risk Score (Step 3, from privacy_score.py)
# --------------------------------------------------

average_risk_score = extract_value(
    privacy_report,
    "Average Risk Score"
)


highest_risk_score = extract_value(
    privacy_report,
    "Highest Risk Score"
)


lowest_risk_score = extract_value(
    privacy_report,
    "Lowest Risk Score"
)






# --------------------------------------------------
# Metadata Minimization Verification
# --------------------------------------------------

def check_minimization():


    result = {}


    if not os.path.exists(ANON_DATASET):

        return {

            "Dataset": "Missing"

        }



    with open(
        ANON_DATASET,
        "r",
        encoding="utf-8"
    ) as file:


        reader = csv.DictReader(file)


        rows = list(reader)



    if len(rows) == 0:

        return {

            "Dataset": "Empty"

        }



    sample = rows[0]



    # UE ID check

    ue = sample.get(
        "UE_ID",
        ""
    )


    if (
        "UE" in ue
        and
        ue[3:].isdigit()
    ):

        result["UE_ID"] = "✓ Pseudonymized"

    else:

        result["UE_ID"] = "✗ Not Pseudonymized"




    # SUCI check

    suci = sample.get(
        "SUCI",
        ""
    )


    if (
        "SUCI" in suci
        and
        suci.replace(
            "SUCI_",
            ""
        ).isdigit()
    ):

        result["SUCI"] = "✓ Pseudonymized"

    else:

        result["SUCI"] = "✗ Not Pseudonymized"





    # gNB IP check

    gnb = sample.get(
        "gNB_IP",
        ""
    )


    if (
        "xxx" in gnb
        or
        "*" in gnb
    ):

        result["gNB_IP"] = "✓ Masked"

    else:

        result["gNB_IP"] = "✗ Exposed"





    # Timestamp check

    timestamp = sample.get(
        "Timestamp",
        ""
    )


    if (
        ":" not in timestamp
        or
        len(timestamp)<15
    ):

        result["Timestamp"] = "✓ Generalized"

    else:

        result["Timestamp"] = "✗ Exact Timestamp"





    # DNN

    dnn = sample.get(
        "DNN",
        ""
    )


    if (
        dnn.lower()
        in
        [
            "generic",
            "masked",
            "unknown",
            "default_dnn"
        ]

    ):

        result["DNN"] = "✓ Generalized"

    else:

        result["DNN"] = "✗ Original"



    # S-NSSAI

    snssai = sample.get(
        "S_NSSAI",
        ""
    )


    if (
        "masked" in snssai.lower()
        or
        "generic" in snssai.lower()
        or
        "default" in snssai.lower()
    ):

        result["S_NSSAI"] = "✓ Generalized"

    else:

        result["S_NSSAI"] = "✗ Original"



    return result






minimization = check_minimization()





# --------------------------------------------------
# Build Summary
# --------------------------------------------------

summary = f"""

========================================================
             CAPSS PRIVACY SUMMARY REPORT
========================================================


PRIVACY SCORE ANALYSIS
--------------------------------------------------------

Source:
privacy_score.py


Average Privacy Score:

{privacy_score}


Highest Exposure Score:

{exposure_score}








========================================================

PRIVACY RISK SCORE

--------------------------------------------------------

Source:
privacy_score.py


Average Risk Score:

{average_risk_score}


Highest Risk Score:

{highest_risk_score}


Lowest Risk Score:

{lowest_risk_score}








========================================================

METADATA MINIMIZATION VERIFICATION

--------------------------------------------------------

Source:
anonymized_registration_dataset.csv


UE IDs:

{minimization.get("UE_ID")}


SUCIs:

{minimization.get("SUCI")}


gNB IP Address:

{minimization.get("gNB_IP")}


Timestamp:

{minimization.get("Timestamp")}


DNN:

{minimization.get("DNN")}


S-NSSAI:

{minimization.get("S_NSSAI")}






========================================================

CORRELATION ANALYSIS

--------------------------------------------------------

Source:
correlation_analyzer.py


{correlation_report}






========================================================

THREAT ANALYSIS

--------------------------------------------------------

Source:
privacy_threat_analyzer.py


{threat_report}





========================================================

FINAL CAPSS PRIVACY OBSERVATION

--------------------------------------------------------

• Privacy score is obtained from the dedicated
  privacy scoring module.


• Metadata minimization status is verified
  directly from anonymized dataset.


• Correlation information is obtained from
  correlation analyzer output.


• CAPSS combines privacy, correlation and
  threat intelligence to generate final
  privacy assessment.



========================================================

"""




# --------------------------------------------------
# Display
# --------------------------------------------------

print(summary)




# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    file.write(summary)



print(
    "Privacy Summary generated successfully!"
)

print(
    OUTPUT_FILE
)