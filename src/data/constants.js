/**
 * Application Constants
 * Centralized configuration values
 */

// Application info
export const APP_NAME = 'DetectSim';
export const APP_VERSION = '1.0.0';
export const APP_DESCRIPTION = 'Detection Engineering RPG';

// Game levels
export const LEVELS = {
  JUNIOR: {
    id: 1,
    name: 'Junior Analyst',
    description: 'Basic pattern matching, single log source, clear indicators',
    prefix: 'L1',
    color: 'blue',
    minRank: 'junior_analyst',
  },
  INTERMEDIATE: {
    id: 2,
    name: 'Intermediate',
    description: 'Multiple conditions, filtering false positives, moderate complexity',
    prefix: 'L2',
    color: 'purple',
    minRank: 'analyst',
  },
  ADVANCED: {
    id: 3,
    name: 'Advanced',
    description: 'Multi-stage attacks, correlation, complex regex, low false positives',
    prefix: 'L3',
    color: 'red',
    minRank: 'senior_analyst',
  },
};

// Difficulty ratings within levels
export const DIFFICULTY = {
  EASY: { value: 1, label: 'Easy', color: 'green' },
  MEDIUM: { value: 2, label: 'Medium', color: 'yellow' },
  HARD: { value: 3, label: 'Hard', color: 'orange' },
  EXPERT: { value: 4, label: 'Expert', color: 'red' },
  NIGHTMARE: { value: 5, label: 'Nightmare', color: 'purple' },
};

// Log source types
export const LOG_SOURCES = {
  PROCESS_CREATION: {
    id: 'process_creation',
    name: 'Process Creation',
    description: 'Windows Security Event 4688 - Process Creation',
    icon: 'Cpu',
  },
  NETWORK: {
    id: 'network',
    name: 'Network Connection',
    description: 'Windows Security Event 5156 - Network Connection',
    icon: 'Globe',
  },
  AUTHENTICATION: {
    id: 'authentication',
    name: 'Authentication',
    description: 'Windows Security Events 4624/4625 - Logon',
    icon: 'Key',
  },
  FILE: {
    id: 'file',
    name: 'File System',
    description: 'Sysmon Event 11 - File Create',
    icon: 'File',
  },
  REGISTRY: {
    id: 'registry',
    name: 'Registry',
    description: 'Sysmon Event 13 - Registry Value Set',
    icon: 'Database',
  },
  DNS: {
    id: 'dns',
    name: 'DNS',
    description: 'DNS Query Events',
    icon: 'Search',
  },
  POWERSHELL: {
    id: 'powershell',
    name: 'PowerShell',
    description: 'PowerShell Script Block Logging - Event 4104',
    icon: 'Terminal',
  },
};

// MITRE ATT&CK Tactics
export const MITRE_TACTICS = {
  RECONNAISSANCE: { id: 'TA0043', name: 'Reconnaissance' },
  RESOURCE_DEVELOPMENT: { id: 'TA0042', name: 'Resource Development' },
  INITIAL_ACCESS: { id: 'TA0001', name: 'Initial Access' },
  EXECUTION: { id: 'TA0002', name: 'Execution' },
  PERSISTENCE: { id: 'TA0003', name: 'Persistence' },
  PRIVILEGE_ESCALATION: { id: 'TA0004', name: 'Privilege Escalation' },
  DEFENSE_EVASION: { id: 'TA0005', name: 'Defense Evasion' },
  CREDENTIAL_ACCESS: { id: 'TA0006', name: 'Credential Access' },
  DISCOVERY: { id: 'TA0007', name: 'Discovery' },
  LATERAL_MOVEMENT: { id: 'TA0008', name: 'Lateral Movement' },
  COLLECTION: { id: 'TA0009', name: 'Collection' },
  COMMAND_AND_CONTROL: { id: 'TA0011', name: 'Command and Control' },
  EXFILTRATION: { id: 'TA0010', name: 'Exfiltration' },
  IMPACT: { id: 'TA0040', name: 'Impact' },
};

// Sigma modifiers supported
export const SIGMA_MODIFIERS = {
  CONTAINS: 'contains',
  ENDSWITH: 'endswith',
  STARTSWITH: 'startswith',
  REGEX: 're',
  ALL: 'all',
  BASE64: 'base64',
  BASE64OFFSET: 'base64offset',
  WIDE: 'wide',
  CIDR: 'cidr',
  GT: 'gt',
  GTE: 'gte',
  LT: 'lt',
  LTE: 'lte',
};

// Feedback types
export const FEEDBACK_TYPES = {
  SUCCESS: 'success',
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info',
};

// View states
export const VIEWS = {
  LANDING: 'landing',
  DASHBOARD: 'dashboard',
  WORKSPACE: 'workspace',
};

// Severity levels for logs
export const SEVERITY = {
  INFO: { label: 'INFO', color: 'gray' },
  WARN: { label: 'WARN', color: 'yellow' },
  ERROR: { label: 'ERROR', color: 'red' },
  CRIT: { label: 'CRIT', color: 'red' },
};

// Default starter code for rule editor
export const DEFAULT_STARTER_CODE = `# Write your detection rule here
# Tips:
# 1. Use YAML syntax
# 2. Define a 'detection' block with 'selection'
# 3. Define a 'condition' to activate detection

detection:
  selection:
    # Add your field filters here
    # Example: Image|endswith: 'powershell.exe'
  condition: selection`;

// Sigma template for hint purchase
export const SIGMA_TEMPLATE = `title: Detection Rule
status: experimental
description: Auto-generated detection rule template
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - 'cmd.exe'
            - 'powershell.exe'
        CommandLine|contains: 'suspicious_flag'
    condition: selection
falsepositives:
    - Legitimate admin activity
level: medium`;

// Animation durations (ms)
export const ANIMATION = {
  FAST: 150,
  NORMAL: 300,
  SLOW: 500,
};

// Local storage keys
export const STORAGE_KEYS = {
  GAME_STATE: 'gamestate',
  USER_PREFERENCES: 'preferences',
  RATE_LIMIT_TRACKER: 'ratelimit',
};

// Rate limiting
export const RATE_LIMITS = {
  DETECTION_SUBMIT: {
    maxAttempts: 20,
    windowMs: 60000, // 1 minute
  },
  HINT_PURCHASE: {
    maxAttempts: 10,
    windowMs: 60000,
  },
};

export default {
  APP_NAME,
  APP_VERSION,
  LEVELS,
  DIFFICULTY,
  LOG_SOURCES,
  MITRE_TACTICS,
  SIGMA_MODIFIERS,
  FEEDBACK_TYPES,
  VIEWS,
  SEVERITY,
  DEFAULT_STARTER_CODE,
  SIGMA_TEMPLATE,
  ANIMATION,
  STORAGE_KEYS,
  RATE_LIMITS,
};
