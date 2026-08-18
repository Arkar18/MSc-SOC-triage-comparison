const text = $json.candidates[0].content.parts[0].text;
const triage = JSON.parse(text);

return [
  {
    json: {
      case_id: $("Sample Wazuh Alert").item.json.case_id,
      method: "LLM-Assisted",
      summary: triage.summary,
      decision: triage.decision,
      severity: triage.severity,
      escalation: triage.escalation,
      confidence: triage.confidence,
      mitre_id: triage.mitre_id,
      mitre_technique: triage.mitre_technique,
      mitre_tactic: triage.mitre_tactic,
      mitre_basis: triage.mitre_basis,
      reasoning: triage.reasoning,
      evidence_used: triage.evidence_used
    }
  }
];
