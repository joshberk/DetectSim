/**
 * Log Generator Utilities
 * Generates raw log strings from structured log objects
 * Supports multiple log source formats
 */

/**
 * Generate Windows Security Event Log (Process Creation - 4688)
 * @param {Object} log - Structured log object
 * @returns {string} Raw log string
 */
export const generateProcessCreationLog = (log) => {
  const parts = [
    `${log.timestamp}`,
    `${log.host}`,
    `MSWinEventLog: [Security]`,
    `[${log.severity || 'INFO'}]`,
    `EventID:4688`,
  ];

  if (log.user) {
    parts.push(`Account Name: "${log.user}"`);
  }
  if (log.image) {
    parts.push(`New Process Name: "${log.image}"`);
  }
  if (log.parentImage) {
    parts.push(`Creator Process Name: "${log.parentImage}"`);
  }
  if (log.commandLine) {
    parts.push(`Process Command Line: "${log.commandLine}"`);
  }
  if (log.processId) {
    parts.push(`New Process ID: "${log.processId}"`);
  }
  if (log.integrityLevel) {
    parts.push(`Integrity Level: "${log.integrityLevel}"`);
  }

  return parts.join(' ');
};

/**
 * Generate Windows Security Event Log (Network Connection)
 * @param {Object} log - Structured log object
 * @returns {string} Raw log string
 */
export const generateNetworkLog = (log) => {
  const parts = [
    `${log.timestamp}`,
    `${log.host}`,
    `MSWinEventLog: [Security]`,
    `[${log.severity || 'INFO'}]`,
    `EventID:5156`,
  ];

  if (log.processName) {
    parts.push(`Application Name: "${log.processName}"`);
  }
  if (log.direction) {
    parts.push(`Direction: "${log.direction}"`);
  }
  if (log.sourceIP) {
    parts.push(`Source Address: "${log.sourceIP}"`);
  }
  if (log.sourcePort) {
    parts.push(`Source Port: "${log.sourcePort}"`);
  }
  if (log.destIP) {
    parts.push(`Destination Address: "${log.destIP}"`);
  }
  if (log.destPort) {
    parts.push(`Destination Port: "${log.destPort}"`);
  }
  if (log.protocol) {
    parts.push(`Protocol: "${log.protocol}"`);
  }

  return parts.join(' ');
};

/**
 * Generate Windows Security Event Log (Authentication - 4624/4625)
 * @param {Object} log - Structured log object
 * @returns {string} Raw log string
 */
export const generateAuthLog = (log) => {
  const eventId = log.success !== false ? '4624' : '4625';
  const parts = [
    `${log.timestamp}`,
    `${log.host}`,
    `MSWinEventLog: [Security]`,
    `[${log.severity || 'INFO'}]`,
    `EventID:${eventId}`,
  ];

  if (log.targetUser) {
    parts.push(`Target User Name: "${log.targetUser}"`);
  }
  if (log.targetDomain) {
    parts.push(`Target Domain Name: "${log.targetDomain}"`);
  }
  if (log.logonType) {
    parts.push(`Logon Type: "${log.logonType}"`);
  }
  if (log.sourceIP) {
    parts.push(`Source Network Address: "${log.sourceIP}"`);
  }
  if (log.sourcePort) {
    parts.push(`Source Port: "${log.sourcePort}"`);
  }
  if (log.workstationName) {
    parts.push(`Workstation Name: "${log.workstationName}"`);
  }
  if (log.failureReason) {
    parts.push(`Failure Reason: "${log.failureReason}"`);
  }
  if (log.status) {
    parts.push(`Status: "${log.status}"`);
  }
  if (log.subStatus) {
    parts.push(`Sub Status: "${log.subStatus}"`);
  }

  return parts.join(' ');
};

/**
 * Generate File System Event Log (Sysmon Event ID 11)
 * @param {Object} log - Structured log object
 * @returns {string} Raw log string
 */
export const generateFileLog = (log) => {
  const parts = [
    `${log.timestamp}`,
    `${log.host}`,
    `Sysmon: [Operational]`,
    `[${log.severity || 'INFO'}]`,
    `EventID:11`,
  ];

  if (log.processName) {
    parts.push(`Image: "${log.processName}"`);
  }
  if (log.targetFilename) {
    parts.push(`TargetFilename: "${log.targetFilename}"`);
  }
  if (log.operation) {
    parts.push(`Operation: "${log.operation}"`);
  }
  if (log.creationUtcTime) {
    parts.push(`CreationUtcTime: "${log.creationUtcTime}"`);
  }
  if (log.hash) {
    parts.push(`Hash: "${log.hash}"`);
  }

  return parts.join(' ');
};

/**
 * Generate Registry Event Log (Sysmon Event ID 13)
 * @param {Object} log - Structured log object
 * @returns {string} Raw log string
 */
export const generateRegistryLog = (log) => {
  const parts = [
    `${log.timestamp}`,
    `${log.host}`,
    `Sysmon: [Operational]`,
    `[${log.severity || 'INFO'}]`,
    `EventID:13`,
  ];

  if (log.processName) {
    parts.push(`Image: "${log.processName}"`);
  }
  if (log.eventType) {
    parts.push(`EventType: "${log.eventType}"`);
  }
  if (log.targetObject) {
    parts.push(`TargetObject: "${log.targetObject}"`);
  }
  if (log.details) {
    parts.push(`Details: "${log.details}"`);
  }

  return parts.join(' ');
};

/**
 * Generate DNS Query Log
 * @param {Object} log - Structured log object
 * @returns {string} Raw log string
 */
export const generateDNSLog = (log) => {
  const parts = [
    `${log.timestamp}`,
    `${log.host}`,
    `DNS-Server: [Analytical]`,
    `[${log.severity || 'INFO'}]`,
  ];

  if (log.processName) {
    parts.push(`ProcessName: "${log.processName}"`);
  }
  if (log.queryName) {
    parts.push(`QueryName: "${log.queryName}"`);
  }
  if (log.queryType) {
    parts.push(`QueryType: "${log.queryType}"`);
  }
  if (log.responseCode) {
    parts.push(`ResponseCode: "${log.responseCode}"`);
  }
  if (log.queryResults) {
    parts.push(`QueryResults: "${log.queryResults}"`);
  }

  return parts.join(' ');
};

/**
 * Generate PowerShell Script Block Log (Event ID 4104)
 * @param {Object} log - Structured log object
 * @returns {string} Raw log string
 */
export const generatePowerShellLog = (log) => {
  const parts = [
    `${log.timestamp}`,
    `${log.host}`,
    `PowerShell: [Operational]`,
    `[${log.severity || 'INFO'}]`,
    `EventID:4104`,
  ];

  if (log.scriptBlockText) {
    parts.push(`ScriptBlockText: "${log.scriptBlockText}"`);
  }
  if (log.scriptPath) {
    parts.push(`Path: "${log.scriptPath}"`);
  }
  if (log.messageNumber) {
    parts.push(`MessageNumber: "${log.messageNumber}"`);
  }
  if (log.messageTotal) {
    parts.push(`MessageTotal: "${log.messageTotal}"`);
  }

  return parts.join(' ');
};

/**
 * Generate raw log based on log source type
 * @param {Object} log - Structured log object
 * @returns {string} Raw log string
 */
export const generateRawLog = (log) => {
  const source = log.logSource || 'process_creation';

  switch (source) {
    case 'process_creation':
      return generateProcessCreationLog(log);
    case 'network':
      return generateNetworkLog(log);
    case 'authentication':
      return generateAuthLog(log);
    case 'file':
      return generateFileLog(log);
    case 'registry':
      return generateRegistryLog(log);
    case 'dns':
      return generateDNSLog(log);
    case 'powershell':
      return generatePowerShellLog(log);
    default:
      return generateProcessCreationLog(log);
  }
};

/**
 * Get field mappings for a log source type
 * @param {string} logSource - Log source type
 * @returns {Object} Field mappings
 */
export const getFieldMappings = (logSource) => {
  const mappings = {
    process_creation: {
      Image: 'image',
      CommandLine: 'commandLine',
      ParentImage: 'parentImage',
      User: 'user',
      Host: 'host',
      ProcessId: 'processId',
      IntegrityLevel: 'integrityLevel',
    },
    network: {
      ProcessName: 'processName',
      SourceIP: 'sourceIP',
      SourcePort: 'sourcePort',
      DestIP: 'destIP',
      DestPort: 'destPort',
      Protocol: 'protocol',
      Direction: 'direction',
      Host: 'host',
    },
    authentication: {
      TargetUser: 'targetUser',
      TargetDomain: 'targetDomain',
      LogonType: 'logonType',
      SourceIP: 'sourceIP',
      SourcePort: 'sourcePort',
      WorkstationName: 'workstationName',
      FailureReason: 'failureReason',
      Status: 'status',
      Host: 'host',
    },
    file: {
      ProcessName: 'processName',
      TargetFilename: 'targetFilename',
      Operation: 'operation',
      Hash: 'hash',
      Host: 'host',
    },
    registry: {
      ProcessName: 'processName',
      TargetObject: 'targetObject',
      EventType: 'eventType',
      Details: 'details',
      Host: 'host',
    },
    dns: {
      ProcessName: 'processName',
      QueryName: 'queryName',
      QueryType: 'queryType',
      ResponseCode: 'responseCode',
      QueryResults: 'queryResults',
      Host: 'host',
    },
    powershell: {
      ScriptBlockText: 'scriptBlockText',
      ScriptPath: 'scriptPath',
      Host: 'host',
    },
  };

  return mappings[logSource] || mappings.process_creation;
};

export default {
  generateRawLog,
  generateProcessCreationLog,
  generateNetworkLog,
  generateAuthLog,
  generateFileLog,
  generateRegistryLog,
  generateDNSLog,
  generatePowerShellLog,
  getFieldMappings,
};
