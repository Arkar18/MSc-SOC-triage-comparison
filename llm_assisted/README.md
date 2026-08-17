## Pre-Experiment Schema Finalisation

Before any official Gemini scenario testing was performed, the LLM-assisted configuration was reviewed against the final dissertation proposal.

The structured output schema was updated to include:

- Alert summary
- MITRE ATT&CK technique ID
- MITRE ATT&CK technique name
- MITRE ATT&CK tactic
- MITRE mapping basis

The prompt was also updated to require MITRE ATT&CK mappings to be supported by the supplied Wazuh evidence and to avoid forcing a mapping when the evidence is insufficient.

This revision was completed before the first official Gemini run to maintain methodological transparency and prevent post-result prompt or schema tuning.

Following this revision, the Gemini model, prompt, structured output schema, and parser are frozen for the official experimental runs.

Each executed scenario receives one official Gemini run only. Outputs are retained as produced and are not rerun or replaced based on result quality.

SC-06 remains Not Executed / N/A due to laboratory limitations.
