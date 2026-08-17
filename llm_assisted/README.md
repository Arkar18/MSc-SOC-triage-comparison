# LLM-Assisted SOC Triage

This directory contains the frozen configuration used for the LLM-assisted triage method in the MSc dissertation experiment.

## Configuration

- Method: LLM-Assisted SOC Triage
- Version: `LLM-GEMINI-v1.0`
- Model: `gemini-3.5-flash`
- API method: `generateContent`
- API version: `v1beta`
- Thinking level: `medium`
- Response format: Structured JSON
- Orchestration platform: n8n

## Experimental Design

The LLM-assisted method receives the same frozen Wazuh evidence supplied to the deterministic rule-based method.

Evidence is manually transferred into n8n as structured JSON to ensure that each triage method evaluates the same evidence.

The LLM is instructed to:

- Act as a Level 1 SOC analyst.
- Analyse only the supplied evidence.
- Avoid inventing or assuming missing facts.
- Prefer investigation when the available evidence is insufficient.
- Produce concise evidence-based reasoning.
- Identify the supplied evidence fields that materially influenced the decision.

The model returns the following fields:

- `decision`
- `severity`
- `escalation`
- `confidence`
- `reasoning`
- `evidence_used`

## Decision Values

The permitted triage decisions are:

- `Benign`
- `Investigate`
- `Escalate`

The corresponding escalation values are:

- `Benign` -> `No escalation`
- `Investigate` -> `Investigate further`
- `Escalate` -> `Escalate to L2`

Severity is restricted to:

- `Low`
- `Medium`
- `High`
- `Critical`

## Configuration Freeze

`LLM-GEMINI-v1.0` was frozen before official LLM-assisted scenario evaluation.

The model, system instruction, thinking level and structured output schema must not be modified in response to individual scenario results.

This prevents scenario-specific tuning and supports a fair comparison with the manual and deterministic rule-based triage methods.

## Files

- `prompt-template.md` — frozen Level 1 SOC analyst prompt.
- `output-schema.json` — structured output schema used for Gemini responses.

## Reproducibility

Scenario evidence is stored separately as frozen JSON inputs.

The same scenario evidence should be used across:

1. Manual triage
2. Rule-based n8n triage
3. LLM-assisted n8n triage

This supports consistent and reproducible comparison between the three methods.
