"""
Profile Matcher Module.

This module provides the ProfileMatcher class which evaluates and scores how well a
given PrivacyScheme satisfies a RequirementProfile based on the scheme's reasoning 
profile and context preferences.
"""

from typing import Dict, Any, List, Tuple
from capss.schemas.context import RequirementProfile
from capss.schemas.scheme import PrivacyScheme


def _to_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val > 0
    if isinstance(val, str):
        v = val.strip().lower()
        return v in ("true", "1", "yes", "high", "critical")
    return bool(val)


class ProfileMatcher:
    """
    A matcher class that compares a requirement profile against a privacy scheme.
    """

    def match(self, requirement_profile: RequirementProfile, scheme: PrivacyScheme) -> float:
        """
        Calculates a compatibility score for a scheme against the provided requirement profile.
        """
        reasoning_profile: Dict[str, Any] = scheme.get_reasoning_profile()
        context_prefs: Dict[str, bool] = scheme.get_context_preferences()

        # Define dimensions and their evaluations
        # Format: (name, is_required, is_supported, weight)
        evaluations: List[Tuple[str, bool, bool, float]] = [
            # -----------------------------------------------------------------
            # Reasoning profile mappings
            # -----------------------------------------------------------------
            (
                'high_threat',
                requirement_profile.threat_level in ['high', 'critical'],
                _to_bool(reasoning_profile.get('high_threat', False)),
                2.0
            ),
            (
                'high_privacy_required',
                requirement_profile.privacy_requirement > 0.6,
                _to_bool(reasoning_profile.get('high_privacy_required', False)),
                1.0
            ),
            (
                'high_metadata_leakage',
                requirement_profile.metadata_leakage_risk > 0.5,
                _to_bool(reasoning_profile.get('high_metadata_leakage', False)),
                2.0
            ),
            (
                'high_tracking_risk',
                requirement_profile.tracking_risk > 0.5,
                _to_bool(reasoning_profile.get('high_tracking_risk', False)),
                2.0
            ),
            (
                'high_correlation_risk',
                requirement_profile.correlation_risk > 0.5,
                _to_bool(reasoning_profile.get('high_correlation_risk', False)),
                2.0
            ),
            (
                'low_latency_required',
                requirement_profile.latency_requirement in ['ultra_low', 'low'],
                _to_bool(reasoning_profile.get('low_latency_required', False)),
                1.0
            ),
            (
                'attack_type_affinity',
                (getattr(requirement_profile, 'attack_type', None) or '').strip().lower() in ['duplicate', 'duplicate_registration', 'flooding', 'invalid_subscriber', 'replay'],
                _to_bool(
                    reasoning_profile.get('attack_type_affinity', {}).get(
                        'duplicate_registration' if (getattr(requirement_profile, 'attack_type', None) or '').strip().lower() in ['duplicate', 'duplicate_registration'] else (getattr(requirement_profile, 'attack_type', None) or '').strip().lower(),
                        False
                    )
                ),
                2.0
            ),
            # -----------------------------------------------------------------
            # Context preferences mappings
            # -----------------------------------------------------------------
            (
                'high_privacy',
                requirement_profile.privacy_requirement > 0.6,
                _to_bool(context_prefs.get('high_privacy', False)),
                1.5
            ),
            (
                'quantum_safe',
                bool(requirement_profile.quantum_threat),
                _to_bool(context_prefs.get('quantum_safe', False)),
                2.0
            ),
            (
                'tracking_risk',
                requirement_profile.tracking_risk > 0.5,
                _to_bool(context_prefs.get('tracking_risk', False)),
                1.3
            ),
            (
                'anonymous_authentication_required',
                bool(requirement_profile.anonymous_auth_required),
                _to_bool(context_prefs.get('anonymous_authentication_required', False)),
                1.0
            ),
            (
                'identity_protection_required',
                bool(requirement_profile.identity_protection_required),
                _to_bool(context_prefs.get('identity_protection_required', False)),
                1.5
            ),
            (
                'resource_constrained',
                requirement_profile.resource_profile == 'constrained',
                _to_bool(context_prefs.get('resource_constrained', False)),
                1.0
            ),
            (
                'low_latency',
                requirement_profile.latency_requirement in ['ultra_low', 'low'],
                _to_bool(context_prefs.get('low_latency', False)),
                1.5
            ),
        ]

        total_score = 0.0
        max_possible_score = 0.0
        min_possible_score = 0.0

        # Calculate scores and min/max boundaries for normalization
        for name, is_req, is_sup, weight in evaluations:
            if is_req and is_sup:
                raw_score = 1.0
            elif is_req and not is_sup:
                raw_score = -0.5
            elif not is_req and is_sup:
                raw_score = 0.0
            else:  # not is_req and not is_sup
                raw_score = 0.25
            
            total_score += weight * raw_score
            
            if is_req:
                max_possible_score += weight * 1.0
                min_possible_score += weight * -0.5
            else:
                max_possible_score += weight * 0.25
                min_possible_score += weight * 0.0

        # Edge case: Avoid division by zero
        if max_possible_score == min_possible_score:
            return 0.0

        # Normalize score to 0.0 - 1.0 range
        normalized_score = (total_score - min_possible_score) / (max_possible_score - min_possible_score)
        
        # Return clamped value to guarantee 0-1 range
        return max(0.0, min(1.0, normalized_score))