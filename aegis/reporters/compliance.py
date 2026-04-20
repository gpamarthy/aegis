from collections import defaultdict

from aegis.core.findings import ComplianceMapping, Finding, OWASPCategory


class ComplianceMapper:
    """Maps OWASP LLM Top 10 categories to EU AI Act, NIST AI RMF, and NIST AI 600-1."""

    _MAPPINGS: dict[OWASPCategory, ComplianceMapping] = {
        OWASPCategory.LLM01: ComplianceMapping(
            owasp=OWASPCategory.LLM01,
            eu_ai_act=["Article 15 - Accuracy, Robustness and Cybersecurity", "Article 9 - Risk Management System"],
            nist_ai_rmf=["MEASURE 2.6 - AI risks from adversarial inputs", "MEASURE 2.7 - AI system security"],
            nist_ai_600=["Prompt Injection - Direct and Indirect"],
            mitre_atlas=["AML.T0051 - LLM Prompt Injection"],
        ),
        OWASPCategory.LLM02: ComplianceMapping(
            owasp=OWASPCategory.LLM02,
            eu_ai_act=["Article 10 - Data and Data Governance", "Article 15 - Accuracy, Robustness and Cybersecurity"],
            nist_ai_rmf=["MEASURE 2.6 - AI risks from adversarial inputs"],
            nist_ai_600=["Information Disclosure - Sensitive Data Leakage"],
            mitre_atlas=["AML.T0024 - Exfiltration via ML Inference API"],
        ),
        OWASPCategory.LLM03: ComplianceMapping(
            owasp=OWASPCategory.LLM03,
            eu_ai_act=["Article 15 - Accuracy, Robustness and Cybersecurity", "Article 9 - Risk Management System"],
            nist_ai_rmf=["GOVERN 1.5 - Ongoing monitoring of AI system components"],
            nist_ai_600=["Supply Chain Compromise - Third-party Models and Data"],
            mitre_atlas=["AML.T0010 - ML Supply Chain Compromise"],
        ),
        OWASPCategory.LLM04: ComplianceMapping(
            owasp=OWASPCategory.LLM04,
            eu_ai_act=["Article 10 - Data and Data Governance", "Article 15 - Accuracy, Robustness and Cybersecurity"],
            nist_ai_rmf=["MEASURE 2.6 - AI risks from adversarial inputs", "MEASURE 2.7 - AI system security"],
            nist_ai_600=["Data Poisoning - Training and Fine-tuning"],
            mitre_atlas=["AML.T0020 - Poisoning Training Data"],
        ),
        OWASPCategory.LLM05: ComplianceMapping(
            owasp=OWASPCategory.LLM05,
            eu_ai_act=["Article 15 - Accuracy, Robustness and Cybersecurity"],
            nist_ai_rmf=["MEASURE 2.6 - AI risks from adversarial inputs"],
            nist_ai_600=["Improper Output Handling - Unvalidated LLM Output"],
            mitre_atlas=["AML.T0043 - Craft Adversarial Data"],
        ),
        OWASPCategory.LLM06: ComplianceMapping(
            owasp=OWASPCategory.LLM06,
            eu_ai_act=["Article 14 - Human Oversight", "Article 15 - Accuracy, Robustness and Cybersecurity"],
            nist_ai_rmf=["GOVERN 1.1 - Legal and regulatory requirements"],
            nist_ai_600=["Excessive Agency - Overprivileged LLM Actions"],
            mitre_atlas=["AML.T0048 - Command and Control via AI"],
        ),
        OWASPCategory.LLM07: ComplianceMapping(
            owasp=OWASPCategory.LLM07,
            eu_ai_act=["Article 15 - Accuracy, Robustness and Cybersecurity", "Article 9 - Risk Management System"],
            nist_ai_rmf=["MEASURE 2.6 - AI risks from adversarial inputs", "MEASURE 2.7 - AI system security"],
            nist_ai_600=["System Prompt Leakage - Meta-prompt Extraction"],
            mitre_atlas=["AML.T0051.001 - Direct Prompt Injection"],
        ),
        OWASPCategory.LLM08: ComplianceMapping(
            owasp=OWASPCategory.LLM08,
            eu_ai_act=["Article 10 - Data and Data Governance", "Article 15 - Accuracy, Robustness and Cybersecurity"],
            nist_ai_rmf=["MEASURE 2.6 - AI risks from adversarial inputs"],
            nist_ai_600=["RAG Data Poisoning - Embedding and Vector Attacks"],
            mitre_atlas=["AML.T0043 - Craft Adversarial Data"],
        ),
        OWASPCategory.LLM09: ComplianceMapping(
            owasp=OWASPCategory.LLM09,
            eu_ai_act=["Article 15 - Accuracy, Robustness and Cybersecurity", "Article 13 - Transparency and Information"],
            nist_ai_rmf=["MEASURE 2.5 - AI system trustworthiness", "MEASURE 2.6 - AI risks from adversarial inputs"],
            nist_ai_600=["Misinformation - Hallucination and Confabulation"],
            mitre_atlas=["AML.T0048 - Influence Operations via AI"],
        ),
        OWASPCategory.LLM10: ComplianceMapping(
            owasp=OWASPCategory.LLM10,
            eu_ai_act=["Article 15 - Accuracy, Robustness and Cybersecurity"],
            nist_ai_rmf=["MEASURE 2.6 - AI risks from adversarial inputs"],
            nist_ai_600=["Unbounded Consumption - Resource Exhaustion"],
            mitre_atlas=["AML.T0029 - Denial of ML Service"],
        ),
    }

    @staticmethod
    def get_mapping(category: OWASPCategory) -> ComplianceMapping:
        """Return the full compliance mapping for an OWASP LLM Top 10 category."""
        return ComplianceMapper._MAPPINGS[category]

    @staticmethod
    def generate_compliance_summary(findings: list[Finding]) -> dict:
        """Generate a summary of findings per OWASP category and compliance framework.

        Returns a dict with:
          - owasp: dict mapping each OWASPCategory value to its finding count
          - eu_ai_act: dict mapping each referenced EU AI Act article to finding count
          - nist_ai_rmf: dict mapping each referenced NIST AI RMF control to finding count
        """
        owasp_counts: dict[str, int] = defaultdict(int)
        eu_ai_act_counts: dict[str, int] = defaultdict(int)
        nist_ai_rmf_counts: dict[str, int] = defaultdict(int)

        for f in findings:
            owasp_counts[f.category.value] += 1

            mapping = ComplianceMapper.get_mapping(f.category)
            for article in mapping.eu_ai_act:
                eu_ai_act_counts[article] += 1
            for control in mapping.nist_ai_rmf:
                nist_ai_rmf_counts[control] += 1

        return {
            "owasp": dict(owasp_counts),
            "eu_ai_act": dict(eu_ai_act_counts),
            "nist_ai_rmf": dict(nist_ai_rmf_counts),
        }
