# MSc-SOC-triage-comparison
MSc dissertation implementation for the comparative evaluation of manual, rule-based, and LLM-assisted SOC alert triage using Wazuh, n8n, Sysmon, and Google Gemini.

Implementation repository for my MSc Computer Science dissertation:

**A Comparative Evaluation of Manual, Rule-Based, and LLM-Assisted SOC Alert Triage Using Wazuh and n8n**

## Project Overview

Security Operations Centres (SOCs) frequently process large volumes of security alerts that require analysts to determine whether activity is benign, requires further investigation, or should be escalated.

This project experimentally compares three Level 1 SOC alert-triage approaches:

1. **Manual Human Triage**
2. **Rule-Based Automation using n8n**
3. **LLM-Assisted Automation using n8n and Google Gemini**

The same controlled security evidence is supplied to each method to support a fair comparison.

The project evaluates differences in areas including:

- triage decision
- severity classification
- escalation recommendation
- triage time
- evidence usage
- reasoning quality
- consistency
- false-positive and false-negative behaviour
- contextual interpretation

## Experimental Environment

The laboratory environment uses:

- **Wazuh SIEM**
- **Sysmon**
- **Windows 11 endpoint**
- **Ubuntu Server**
- **n8n**
- **Google Gemini API**
- **VMware Workstation**

Wazuh and Sysmon provide the security telemetry used during scenario execution.

For experimental consistency, relevant alert evidence is frozen after collection and supplied to the automation workflows in a structured format.

## Repository Structure

```text
MSc-SOC-triage-comparison/
│
├── rule-based/
│   ├── RB-GENERIC-v1.0.js
│   └── README.md
│
├── llm-assisted/
│   ├── prompt-template.md
│   ├── output-schema.json
│   └── README.md
│
├── n8n-workflows/
│   ├── rule-based-workflow.json
│   ├── llm-assisted-workflow.json
│   └── README.md
│
├── docs/
│   ├── architecture.md
│   ├── rule-based-implementation.md
│   ├── llm-implementation.md
│   └── experiment-method.md
│
├── config-examples/
│   └── evidence-input-template.json
│
├── .gitignore
└── README.md
```

## Rule-Based Triage

The rule-based workflow implements a deterministic Level 1 SOC playbook.

Structured alert evidence is evaluated against predefined generic security conditions. These include areas such as:

- authentication anomalies
- account and privilege changes
- persistence activity
- credential-access indicators
- script and command execution
- discovery behaviour
- file-integrity changes
- malware detections
- SIEM alert severity

Rules are evaluated in a predefined priority order.

The workflow does **not** use scenario identifiers or expected scenario outcomes when making triage decisions.

The official experimental version is maintained as:

```text
RB-GENERIC-v1.0
```

Once frozen for official evaluation, this version is not modified in response to individual scenario results.

## LLM-Assisted Triage

The LLM-assisted workflow uses n8n to provide structured Wazuh evidence to Google Gemini.

The model is instructed to act as a Level 1 SOC analyst and return a structured triage response.

The repository will document:

- prompt design
- evidence supplied to the model
- output schema
- n8n workflow configuration
- model configuration
- experimental controls

API credentials and other secrets are **not stored in this repository**.

## Manual Triage

Manual triage acts as the human comparison method.

The analyst reviews the same frozen security evidence and records a triage decision, severity level, escalation recommendation, supporting evidence, reasoning, and triage time.

Raw experimental results are maintained separately from the implementation source code.

## Reproducibility and Version Control

Git version control is used to preserve the implementation used during the dissertation experiment.

In particular, the deterministic rule-based playbook is versioned and frozen before processing the official experimental cases. This reduces the risk of modifying the automation logic to fit known scenario outcomes.

## Security and Privacy

This repository must not contain:

- API keys
- passwords
- authentication tokens
- Wazuh credentials
- n8n credentials
- university credentials
- personally identifiable information
- unsanitised sensitive security evidence

Example configuration files use placeholder values where credentials or environment-specific information would otherwise be required.

## Academic Context

This repository contains implementation artefacts developed specifically for an MSc dissertation.

The rule-based implementation is an author-developed deterministic SOC triage playbook. Academic cybersecurity-playbook research and relevant technical standards are used to inform the design principles; the implementation is not presented as a reproduction of an existing playbook algorithm.

Detailed references and methodological justification are provided in the accompanying dissertation.

## Status

**Development and experimental evaluation in progress.**

Repository contents will be updated as the rule-based and LLM-assisted workflows are finalised and evaluated.
