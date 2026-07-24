"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    calculator.py

Purpose
-------
Calculates a context-aware threat score from the
Pre-AMF Security Layer outputs.

The threat score ranges from 0 to 100.

This module contains NO reporting or CSV generation.
"""

from systems.pre_amf.models import ValidationContext
from systems.threat_context.models import ThreatFactors


class ThreatCalculator:
    """
    Computes the overall threat score from
    validator and detector outputs.
    """

    def calculate(self, context: ValidationContext):

        factors = ThreatFactors()

        # ==================================================
        # Duplicate Detector
        # ==================================================

        if context.duplicate_result is not None:

            if context.duplicate_result.detected:

                factors.duplicate_score = (
                    context.duplicate_result.confidence * 25
                )

        # ==================================================
        # Registration Rate Detector
        # ==================================================

        if context.rate_result is not None:

            if context.rate_result.detected:

                factors.rate_score = (
                    context.rate_result.confidence * 30
                )

        # ==================================================
        # Subscriber Validation
        # ==================================================

        if context.subscriber_result is not None:

            if not context.subscriber_result.passed:

                factors.subscriber_score = 20

        # ==================================================
        # Header Validation
        # ==================================================

        if context.header_result is not None:

            if not context.header_result.passed:

                factors.header_score = 10

        # ==================================================
        # Parameter Validation
        # ==================================================

        if context.parameter_result is not None:

            if not context.parameter_result.passed:

                factors.parameter_score = 10

        # ==================================================
        # Historical Behaviour
        # ==================================================

        history = context.history

        history_score = 0

        history_score += min(history.registration_count, 5)

        history_score += min(history.duplicate_count * 2, 10)

        history_score += min(history.failed_attempts * 2, 10)

        factors.history_score = history_score

        # ==================================================
        # Final Threat Score
        # ==================================================

        threat_score = (

            factors.duplicate_score +

            factors.rate_score +

            factors.subscriber_score +

            factors.header_score +

            factors.parameter_score +

            factors.history_score

        )

        threat_score = round(min(threat_score, 100), 2)

        # ==================================================
        # Confidence
        # ==================================================

        confidence = 0.0

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

        return threat_score, confidence, factors