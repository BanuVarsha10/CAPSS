"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    report.py

Purpose
-------
Generates standardized attack reports from the
Pre-AMF Security Layer.

This module converts the ValidationContext into an
AttackReport that can later be consumed by:

• Privacy Module
• AI Recommendation Engine
• CSV Export
• Result Reporting

No validation or attack detection logic exists here.
"""

from pathlib import Path
import csv

from systems.pre_amf.models import (
    ValidationContext,
    AttackReport,
)


class ReportGenerator:
    """
    Generates AttackReport objects and exports them.
    """

    def __init__(self):

        self.reports = []

    # ======================================================
    # Build Report
    # ======================================================

    def build_report(
        self,
        context: ValidationContext,
    ) -> AttackReport:

        confidence = 0.0

        # --------------------------------------------------
        # Highest detector confidence
        # --------------------------------------------------

        if context.duplicate_result is not None:

            confidence = max(

                confidence,

                context.duplicate_result.confidence

            )

        if context.rate_result is not None:

            confidence = max(

                confidence,

                context.rate_result.confidence

            )

        report = AttackReport(

            request_id=context.request.request_id,

            experiment_name=context.request.experiment_name,

            timestamp=context.request.timestamp,

            ue_id=context.request.ue_id,

            attack_detected=context.classification_result.attack_flag,

            attack_type=context.classification_result.attack_type,

            decision=context.classification_result.decision,

            severity=context.classification_result.severity,

            confidence=confidence,

            risk_score=0.0,

            reasons=context.classification_result.reasons

        )

        self.reports.append(report)

        return report

    # ======================================================
    # Export CSV
    # ======================================================

    def export_csv(
        self,
        output_file,
    ):

        output_file = Path(output_file)

        output_file.parent.mkdir(

            parents=True,

            exist_ok=True

        )

        with open(

            output_file,

            "w",

            newline="",

            encoding="utf-8"

        ) as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow([

                "Request_ID",

                "Experiment",

                "Timestamp",

                "UE_ID",

                "Attack_Detected",

                "Attack_Type",

                "Decision",

                "Severity",

                "Confidence",

                "Risk_Score",

                "Reasons",

            ])

            for report in self.reports:

                writer.writerow([

                    report.request_id,

                    report.experiment_name,

                    report.timestamp,

                    report.ue_id,

                    report.attack_detected,

                    report.attack_type,

                    report.decision,

                    report.severity,

                    report.confidence,

                    report.risk_score,

                    " | ".join(report.reasons),

                ])

    # ======================================================
    # Summary
    # ======================================================

    def print_summary(
        self,
    ):

        print()

        print("=" * 60)

        print("Pre-AMF Security Report")

        print("=" * 60)

        print(f"Total Requests : {len(self.reports)}")

        attacks = sum(

            report.attack_detected

            for report in self.reports

        )

        print(f"Attacks Found  : {attacks}")

        print(f"Normal Traffic : {len(self.reports) - attacks}")

        print("=" * 60)


# ==========================================================
# Convenience Functions
# ==========================================================

def generate_report(
    context: ValidationContext,
) -> AttackReport:

    generator = ReportGenerator()

    return generator.build_report(context)


def export_reports(
    reports,
    output_file,
):
    """
    Export a list of AttackReport objects.
    """

    generator = ReportGenerator()

    generator.reports = reports

    generator.export_csv(output_file)