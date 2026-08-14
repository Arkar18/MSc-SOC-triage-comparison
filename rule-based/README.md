# Rule-Based SOC Triage Workflow

This directory contains the deterministic rule-based triage implementation used in the MSc dissertation experiment.

## Official Playbook Version

```text
RB-GENERIC-v1.0
```

The playbook was frozen before processing the official experimental scenarios.

## Design

The workflow implements a generic Level 1 SOC triage playbook using predefined security conditions.

It evaluates structured security evidence including fields such as:

- SIEM rule severity
- Windows event ID
- process image
- command line
- parent process
- authentication counts
- account and group information
- process-access evidence
- scheduled-task information
- service information
- registry activity
- file-integrity information

The decision logic is deterministic and priority based.

Higher-priority security behaviours are evaluated before lower-priority conditions and fallback SIEM severity rules.

The possible triage decisions are:

```text
Benign
Investigate
Escalate
```

The associated severity classifications are:

```text
Low
Medium
High
Critical
```

## Scenario Independence

The playbook does not use experimental scenario identifiers to determine its triage output.

Scenario-specific usernames, filenames, task names, expected outcomes, and ground-truth labels are not included in the decision logic.

The intention is to evaluate a reusable deterministic SOC playbook rather than a workflow engineered specifically for the dissertation scenario set.

## Development and Freeze Procedure

An earlier development implementation was replaced before official evaluation.

The final generic playbook was mechanically validated using synthetic security inputs before being frozen as:

```text
RB-GENERIC-v1.0
```

After freezing the playbook, its decision logic is not modified based on the results of individual experimental scenarios.

Unexpected classifications, false positives, false negatives, or limitations are retained as experimental findings.

## Implementation

The playbook is implemented in JavaScript and executed inside an n8n Code node.

The source file is:

```text
RB-GENERIC-v1.0.js
```

The implementation returns structured output containing:

- policy version
- matched playbook rule
- triage decision
- severity
- escalation recommendation
- reasoning
- evidence fields used
- matched conditions

## Academic Basis

The implementation is author-developed.

Its design principles are informed by academic research on cybersecurity incident-response playbooks, structured rule-based workflows, and machine-readable security automation.

The exact JavaScript implementation and individual decision rules are not claimed to have been copied from an existing published algorithm or code repository.
