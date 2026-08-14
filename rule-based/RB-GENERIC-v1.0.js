const items = $input.all();

const text = (v) => String(v ?? '').toLowerCase();

const num = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
};

const arr = (v) => {
  if (Array.isArray(v)) return v;
  if (v === undefined || v === null || v === '') return [];
  return [v];
};

const hasValue = (v) => {
  if (Array.isArray(v)) return v.length > 0;
  if (v === undefined || v === null) return false;
  if (typeof v === 'string') return v.trim() !== '';
  return true;
};

return items.map((item) => {

  const d = item.json;

  const ruleLevel = num(d.rule_level);
  const eventId = num(d.event_id);

  const commandLine = text(d.command_line);
  const image = text(d.image);
  const parentImage = text(d.parent_image);
  const ruleDescription = text(d.rule_description);

  const targetUser = text(d.target_user);
  const groupName = text(d.group_name);

  const targetProcess = text(d.target_process);
  const targetImage = text(d.target_image);

  const registryKey = text(d.registry_key);
  const registryValue = text(d.registry_value_data);

  const serviceName = text(d.service_name);
  const servicePath = text(d.service_image_path);

  const filePath = text(d.file_path);
  const fileAction = text(d.file_action);

  const taskName = text(d.task_name);
  const taskAction = text(d.task_action);
  const taskRunAs = text(d.task_run_as);

  const failedLogins = num(d.failed_login_count);
  const successfulLogins = num(d.successful_login_count);

  const evidenceUsed = new Set();
  const matchedConditions = [];

  const record = (condition, fields = []) => {
    matchedConditions.push(condition);

    fields.forEach((field) => {
      if (hasValue(d[field])) {
        evidenceUsed.add(field);
      }
    });
  };

  // =====================================================
  // GENERIC SECURITY BEHAVIOUR DETECTION
  // =====================================================

  // Authentication anomaly
  const repeatedFailures = failedLogins >= 5;

  const failureThenSuccess =
    failedLogins >= 5 &&
    successfulLogins >= 1;

  // Local account creation
  const accountCreation =
    eventId === 4720 ||
    (
      /\bnet(\.exe)?\s+user\b/i.test(commandLine) &&
      (
        commandLine.includes('/add') ||
        commandLine.includes(' add ')
      )
    );

  // Privileged group membership change
  const privilegedGroups = [
    'administrators',
    'domain admins',
    'enterprise admins'
  ];

  const privilegedGroup =
    privilegedGroups.some((g) => groupName.includes(g));

  const privilegedGroupChange =
    (
      [4728, 4732, 4756].includes(eventId) &&
      privilegedGroup
    ) ||
    (
      /net(\.exe)?\s+localgroup\s+administrators/i.test(commandLine) &&
      (
        commandLine.includes('/add') ||
        commandLine.includes(' add ')
      )
    );

  // Credential-access style process access
  const lsassMentioned =
    targetProcess.includes('lsass') ||
    targetImage.includes('lsass') ||
    ruleDescription.includes('lsass');

  const credentialAccess =
    (
      eventId === 10 &&
      lsassMentioned
    ) ||
    ruleDescription.includes('credential dumping');

  // Scheduled task creation
  const scheduledTaskCreation =
    (
      commandLine.includes('schtasks') &&
      commandLine.includes('/create')
    ) ||
    (
      taskName !== '' &&
      taskAction !== ''
    );

  // Service creation
  const serviceCreation =
    /\bsc(\.exe)?\s+create\b/i.test(commandLine) ||
    eventId === 7045 ||
    (
      ruleDescription.includes('service') &&
      (
        ruleDescription.includes('created') ||
        ruleDescription.includes('installed')
      )
    );

  // Registry / autostart creation
  const autorunPersistence =
    registryKey.includes('currentversion\\run') ||
    registryKey.includes('currentversion\\runonce') ||
    commandLine.includes('currentversion\\run') ||
    commandLine.includes('currentversion\\runonce');

  const persistenceCreated =
    scheduledTaskCreation ||
    serviceCreation ||
    autorunPersistence;

  // Privileged execution context
  const privilegedExecution =
    taskRunAs === 'system' ||
    commandLine.includes('/ru system') ||
    commandLine.includes('/ru "system"') ||
    text(d.integrity_level) === 'system';

  // User-writable / temporary execution locations
  const suspiciousWritablePath =
    commandLine.includes('\\users\\public\\') ||
    commandLine.includes('\\appdata\\') ||
    commandLine.includes('\\temp\\') ||
    servicePath.includes('\\users\\public\\') ||
    servicePath.includes('\\appdata\\') ||
    servicePath.includes('\\temp\\');

  const privilegedPersistence =
    persistenceCreated &&
    (
      privilegedExecution ||
      suspiciousWritablePath
    );

  // Script/interpreter based network or file retrieval
  const interpreter =
    image.includes('powershell') ||
    image.includes('pwsh') ||
    image.includes('cmd.exe') ||
    parentImage.includes('powershell') ||
    parentImage.includes('pwsh');

  const transferKeywords = [
    'invoke-webrequest',
    'start-bitstransfer',
    'downloadstring',
    'webclient',
    'curl ',
    'wget ',
    'http://',
    'https://'
  ];

  const networkTransfer =
    interpreter &&
    transferKeywords.some((k) => commandLine.includes(k));

  // Higher-risk script execution indicators
  const scriptRiskKeywords = [
    '-encodedcommand',
    'frombase64string',
    'invoke-expression',
    'iex(',
    'executionpolicy bypass',
    '-windowstyle hidden'
  ];

  const suspiciousScriptExecution =
    interpreter &&
    scriptRiskKeywords.some((k) => commandLine.includes(k));

  // Discovery behaviour
  const discoverySource = [
    commandLine,
    ...arr(d.commands_alerted).map(text)
  ].join(' ');

  const discoveryPatterns = [
    /\bwhoami\b/i,
    /\bhostname\b/i,
    /\bipconfig\b/i,
    /\barp\s+-a\b/i,
    /\broute\s+print\b/i,
    /\bnet\s+user\b/i,
    /\bnet\s+localgroup\b/i,
    /\bnetstat\b/i,
    /\bsysteminfo\b/i,
    /\btasklist\b/i
  ];

  const discoveryCount =
    discoveryPatterns.filter((r) => r.test(discoverySource)).length;

  const multipleDiscovery = discoveryCount >= 3;

  // File integrity modification
  const fileModified =
    fileAction.includes('modified') ||
    fileAction.includes('changed') ||
    (
      hasValue(d.old_hash) &&
      hasValue(d.new_hash) &&
      text(d.old_hash) !== text(d.new_hash)
    );

  // Malware / AV detection
  const malwareDetected =
    ruleDescription.includes('malware') ||
    ruleDescription.includes('virus') ||
    ruleDescription.includes('trojan') ||
    ruleDescription.includes('threat detected') ||
    ruleDescription.includes('antivirus');

  const malwareContained =
    malwareDetected &&
    (
      ruleDescription.includes('quarantine') ||
      ruleDescription.includes('quarantined') ||
      ruleDescription.includes('removed') ||
      fileAction.includes('quarantine') ||
      fileAction.includes('removed')
    );

  // Routine administrative / inventory behaviour
  const inventoryKeywords = [
    'get-computerinfo',
    'get-ciminstance',
    'get-volume',
    'get-service',
    'systeminfo'
  ];

  const inventoryMatches =
    inventoryKeywords.filter((k) => commandLine.includes(k)).length;

  const routineInventory =
    inventoryMatches >= 2 &&
    !networkTransfer &&
    !suspiciousScriptExecution &&
    !persistenceCreated &&
    !credentialAccess;

  // =====================================================
  // GENERIC L1 DECISION PLAYBOOK
  // Highest-priority rules are evaluated first.
  // =====================================================

  let decision;
  let severity;
  let escalation;
  let playbookRule;
  let reasoning;

  // -----------------------------------------------------
  // CRITICAL — SIEM indicates extreme severity
  // -----------------------------------------------------

  if (ruleLevel >= 12) {

    record(
      'Very high SIEM rule severity',
      ['rule_level']
    );

    decision = 'Escalate';
    severity = 'Critical';
    escalation = 'Escalate to L2';
    playbookRule = 'RB-CRIT-01';

    reasoning =
      'The SIEM assigned a very high rule severity. The event requires immediate escalation for deeper investigation.';

  }

  // -----------------------------------------------------
  // HIGH — Credential access
  // -----------------------------------------------------

  else if (credentialAccess) {

    record(
      'Credential-access behaviour involving a sensitive authentication process',
      ['event_id', 'target_process', 'target_image', 'rule_description']
    );

    decision = 'Escalate';
    severity = 'High';
    escalation = 'Escalate to L2';
    playbookRule = 'RB-HIGH-01';

    reasoning =
      'Process-access evidence indicates potential credential-access activity involving a sensitive authentication process.';

  }

  // -----------------------------------------------------
  // HIGH — Privileged account/group modification
  // -----------------------------------------------------

  else if (privilegedGroupChange) {

    record(
      'Privileged group membership modification detected',
      ['event_id', 'group_name', 'target_user', 'command_line']
    );

    decision = 'Escalate';
    severity = 'High';
    escalation = 'Escalate to L2';
    playbookRule = 'RB-HIGH-02';

    reasoning =
      'An account was added to a privileged administrative group, requiring escalation to verify authorisation.';

  }

  // -----------------------------------------------------
  // HIGH — Failed authentication followed by success
  // -----------------------------------------------------

  else if (failureThenSuccess) {

    record(
      'Successful authentication followed repeated failures',
      ['failed_login_count', 'successful_login_count']
    );

    decision = 'Escalate';
    severity = 'High';
    escalation = 'Escalate to L2';
    playbookRule = 'RB-HIGH-03';

    reasoning =
      'Repeated authentication failures followed by a successful login may indicate successful credential compromise.';

  }

  // -----------------------------------------------------
  // HIGH — Privileged persistence
  // -----------------------------------------------------

  else if (privilegedPersistence) {

    record(
      'Persistence mechanism created with privileged or higher-risk execution context',
      [
        'command_line',
        'task_name',
        'task_action',
        'task_run_as',
        'service_name',
        'service_image_path',
        'registry_key'
      ]
    );

    decision = 'Escalate';
    severity = 'High';
    escalation = 'Escalate to L2';
    playbookRule = 'RB-HIGH-04';

    reasoning =
      'A persistence mechanism was created with privileged execution or a higher-risk execution location.';

  }

  // -----------------------------------------------------
  // HIGH — Suspicious encoded/hidden script execution
  // -----------------------------------------------------

  else if (suspiciousScriptExecution) {

    record(
      'Higher-risk script execution indicators detected',
      ['image', 'command_line', 'parent_image']
    );

    decision = 'Escalate';
    severity = 'High';
    escalation = 'Escalate to L2';
    playbookRule = 'RB-HIGH-05';

    reasoning =
      'The command contains execution characteristics commonly associated with concealed or obfuscated script activity.';

  }

  // -----------------------------------------------------
  // HIGH — High SIEM severity fallback
  // -----------------------------------------------------

  else if (ruleLevel >= 10) {

    record(
      'High SIEM rule severity',
      ['rule_level']
    );

    decision = 'Escalate';
    severity = 'High';
    escalation = 'Escalate to L2';
    playbookRule = 'RB-HIGH-06';

    reasoning =
      'The SIEM assigned a high rule severity and no stronger contextual rule superseded it.';

  }

  // -----------------------------------------------------
  // MEDIUM — Persistence creation
  // -----------------------------------------------------

  else if (persistenceCreated) {

    record(
      'Persistence mechanism creation detected',
      [
        'command_line',
        'task_name',
        'task_action',
        'service_name',
        'service_image_path',
        'registry_key',
        'registry_value_data'
      ]
    );

    decision = 'Investigate';
    severity = 'Medium';
    escalation = 'Investigate further';
    playbookRule = 'RB-MED-01';

    reasoning =
      'A persistence mechanism was created and should be investigated to determine whether the activity was authorised.';

  }

  // -----------------------------------------------------
  // MEDIUM — Account creation
  // -----------------------------------------------------

  else if (accountCreation) {

    record(
      'Local account creation detected',
      ['event_id', 'target_user', 'command_line']
    );

    decision = 'Investigate';
    severity = 'Medium';
    escalation = 'Investigate further';
    playbookRule = 'RB-MED-02';

    reasoning =
      'A new local account was created. The creator and business purpose should be verified.';

  }

  // -----------------------------------------------------
  // MEDIUM — Repeated authentication failures
  // -----------------------------------------------------

  else if (repeatedFailures) {

    record(
      'Repeated authentication failures detected',
      ['failed_login_count']
    );

    decision = 'Investigate';
    severity = 'Medium';
    escalation = 'Investigate further';
    playbookRule = 'RB-MED-03';

    reasoning =
      'Multiple authentication failures occurred and should be investigated for possible password guessing or user error.';

  }

  // -----------------------------------------------------
  // MEDIUM — Script/interpreter network transfer
  // -----------------------------------------------------

  else if (networkTransfer) {

    record(
      'Script or command interpreter performed network/file retrieval',
      ['image', 'command_line', 'parent_image']
    );

    decision = 'Investigate';
    severity = 'Medium';
    escalation = 'Investigate further';
    playbookRule = 'RB-MED-04';

    reasoning =
      'A command interpreter performed network or file retrieval activity that requires source and destination validation.';

  }

  // -----------------------------------------------------
  // MEDIUM — Multiple discovery behaviours
  // -----------------------------------------------------

  else if (multipleDiscovery) {

    record(
      'Multiple discovery behaviours detected',
      ['command_line', 'commands_alerted']
    );

    decision = 'Investigate';
    severity = 'Medium';
    escalation = 'Investigate further';
    playbookRule = 'RB-MED-05';

    reasoning =
      'Multiple system, account, or network discovery behaviours were observed and should be correlated with surrounding activity.';

  }

  // -----------------------------------------------------
  // MEDIUM — File integrity modification
  // -----------------------------------------------------

  else if (fileModified) {

    record(
      'Monitored file modification detected',
      ['file_path', 'file_action', 'old_hash', 'new_hash']
    );

    decision = 'Investigate';
    severity = 'Medium';
    escalation = 'Investigate further';
    playbookRule = 'RB-MED-06';

    reasoning =
      'A monitored file changed. The modification should be validated against authorised administrative activity.';

  }

  // -----------------------------------------------------
  // MEDIUM — Malware detection
  // -----------------------------------------------------

  else if (malwareDetected) {

    record(
      malwareContained
        ? 'Malware detection with containment evidence'
        : 'Malware detection without confirmed containment',
      ['rule_description', 'file_path', 'file_action']
    );

    decision = malwareContained ? 'Investigate' : 'Escalate';
    severity = malwareContained ? 'Medium' : 'High';
    escalation = malwareContained
      ? 'Investigate further'
      : 'Escalate to L2';

    playbookRule = malwareContained
      ? 'RB-MED-07'
      : 'RB-HIGH-07';

    reasoning = malwareContained
      ? 'Malware-related activity was detected with evidence of containment; verification is still required.'
      : 'Malware-related activity was detected without confirmed containment and requires escalation.';

  }

  // -----------------------------------------------------
  // MEDIUM — Elevated SIEM severity fallback
  // -----------------------------------------------------

  else if (ruleLevel >= 7) {

    record(
      'Elevated SIEM rule severity',
      ['rule_level']
    );

    decision = 'Investigate';
    severity = 'Medium';
    escalation = 'Investigate further';
    playbookRule = 'RB-MED-08';

    reasoning =
      'The SIEM assigned an elevated rule severity and the event requires further investigation.';

  }

  // -----------------------------------------------------
  // BENIGN CONTROL — Routine administrative inventory
  // -----------------------------------------------------

  else if (routineInventory && ruleLevel < 7) {

    record(
      'Routine system inventory behaviour without additional risk indicators',
      ['image', 'command_line', 'parent_image']
    );

    decision = 'Benign';
    severity = 'Low';
    escalation = 'No escalation';
    playbookRule = 'RB-LOW-01';

    reasoning =
      'The observed activity consists primarily of standard system-inventory commands with no additional predefined risk indicators.';

  }

  // -----------------------------------------------------
  // LOW — Moderate SIEM severity fallback
  // -----------------------------------------------------

  else if (ruleLevel >= 4) {

    record(
      'Moderate SIEM rule severity',
      ['rule_level']
    );

    decision = 'Investigate';
    severity = 'Low';
    escalation = 'Investigate further';
    playbookRule = 'RB-LOW-02';

    reasoning =
      'No higher-priority playbook condition matched. The SIEM severity warrants low-priority investigation.';

  }

  // -----------------------------------------------------
  // DEFAULT
  // -----------------------------------------------------

  else {

    if (ruleLevel > 0) {
      record(
        'Low SIEM rule severity with no additional predefined indicators',
        ['rule_level']
      );
    }

    decision = 'Benign';
    severity = 'Low';
    escalation = 'No escalation';
    playbookRule = 'RB-LOW-03';

    reasoning =
      'No predefined higher-risk behaviour matched the supplied evidence.';
  }

  return {
    json: {
      case_id: d.case_id,
      method: 'Rule-Based',
      policy_version: 'RB-GENERIC-v1.0',
      playbook_rule: playbookRule,
      decision,
      severity,
      escalation,
      confidence: 100,
      confidence_basis:
        'The output is deterministic for the supplied evidence and fixed playbook rules; confidence is not a probability of correctness.',
      reasoning,
      evidence_used: [...evidenceUsed],
      matched_conditions: matchedConditions
    }
  };
});
