"""
Explainable AI (XAI) Attribution & Forensic Reasoning Engine
"""

from typing import Dict, Any, List

class XAIExplainer:
    @staticmethod
    def generate_explanation(eval_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Constructs transparent, human-readable forensic explanations for security analysts.
        """
        score = eval_data.get("risk_score", 0.0)
        severity = eval_data.get("severity", "LOW")
        indicators = eval_data.get("indicators", [])
        sub_scores = eval_data.get("sub_scores", {})

        # Find highest contributing risk vector
        sorted_vectors = sorted(sub_scores.items(), key=lambda x: x[1], reverse=True)
        primary_vector = sorted_vectors[0][0].upper() if sorted_vectors else "GENERAL"

        # Build natural language narrative summary
        if score >= 85:
            narrative = f"CRITICAL THREAT: Risk score of {score}/100. High probability of malicious phishing or fraud. Primary risk vector: {primary_vector}."
        elif score >= 60:
            narrative = f"HIGH THREAT: Risk score of {score}/100. Significant social engineering indicators present. Primary risk vector: {primary_vector}."
        elif score >= 35:
            narrative = f"MODERATE THREAT: Risk score of {score}/100. Minor anomalies detected. Primary risk vector: {primary_vector}."
        else:
            narrative = f"LOW THREAT: Risk score of {score}/100. Standard traffic behavior; no major attack signatures found."

        confidence = round(min(99.9, 72.0 + (score * 0.25)), 1)

        return {
            "narrative_summary": narrative,
            "primary_vector": primary_vector,
            "confidence_rating": f"{confidence}%",
            "vector_scores": sub_scores,
            "attributions": indicators
        }
