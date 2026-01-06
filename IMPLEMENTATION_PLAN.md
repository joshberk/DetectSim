# DetectSim Implementation Plan

## Overview

Transform the single-file DetectSim prototype into a production-ready, modular application with 75 real-world detection scenarios, enhanced Sigma parsing with regex support, comprehensive economy system, and OWASP-compliant security.

---

## Phase 1: Project Setup & Architecture

### 1.1 Initialize Vite Project
```bash
npm create vite@latest . -- --template react
npm install tailwindcss postcss autoprefixer
npm install lucide-react
npm install firebase
npm install dompurify  # XSS prevention
```

### 1.2 Project Structure
```
DetectSim/
├── public/
│   └── index.html
├── src/
│   ├── components/
│   │   ├── views/
│   │   │   ├── Landing.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   └── Workspace.jsx
│   │   ├── workspace/
│   │   │   ├── LogViewer.jsx
│   │   │   ├── CodeEditor.jsx
│   │   │   ├── Briefing.jsx
│   │   │   └── FeedbackPanel.jsx
│   │   ├── dashboard/
│   │   │   ├── CareerMap.jsx
│   │   │   ├── UserProfile.jsx
│   │   │   ├── StatsPanel.jsx
│   │   │   └── Leaderboard.jsx
│   │   └── ui/
│   │       ├── Button.jsx
│   │       ├── Badge.jsx
│   │       ├── ProgressBar.jsx
│   │       └── Modal.jsx
│   ├── engine/
│   │   ├── SigmaParser.js
│   │   ├── SigmaValidator.js
│   │   ├── RegexEngine.js
│   │   └── DetectionEngine.js
│   ├── data/
│   │   ├── scenarios/
│   │   │   ├── index.js
│   │   │   ├── level1-junior.js      # 25 scenarios
│   │   │   ├── level2-intermediate.js # 25 scenarios
│   │   │   └── level3-advanced.js     # 25 scenarios
│   │   ├── logTemplates.js
│   │   ├── constants.js
│   │   └── ranks.js
│   ├── hooks/
│   │   ├── useAuth.js
│   │   ├── useGameState.js
│   │   ├── useLeaderboard.js
│   │   └── useScoring.js
│   ├── services/
│   │   ├── firebase.js
│   │   └── storage.js
│   ├── utils/
│   │   ├── sanitize.js
│   │   ├── scoring.js
│   │   ├── logGenerator.js
│   │   └── validation.js
│   ├── context/
│   │   └── GameContext.jsx
│   ├── App.jsx
│   ├── main.jsx
│   └── index.css
├── .env.example
├── package.json
├── tailwind.config.js
├── vite.config.js
└── README.md
```

---

## Phase 2: Enhanced Sigma Parser with Regex

### 2.1 Supported Features

| Feature | Syntax | Example |
|---------|--------|---------|
| **Exact Match** | `Field: value` | `Image: cmd.exe` |
| **Contains** | `Field\|contains:` | `CommandLine\|contains: '-enc'` |
| **Endswith** | `Field\|endswith:` | `Image\|endswith: 'powershell.exe'` |
| **Startswith** | `Field\|startswith:` | `Image\|startswith: 'C:\\Windows'` |
| **Regex** | `Field\|re:` | `CommandLine\|re: '(?i)invoke-(expression\|command)'` |
| **All modifier** | `Field\|all\|contains:` | Must match ALL values |
| **Lists** | YAML list syntax | `- 'value1'` |
| **AND Logic** | Multiple selections | `selection1 AND selection2` |
| **OR Logic** | Condition syntax | `selection1 OR selection2` |
| **NOT Logic** | Condition syntax | `NOT filter` |
| **Count** | `count(field) > N` | For frequency-based detection |

### 2.2 Parser Architecture

```javascript
// SigmaParser.js - Core parsing
class SigmaParser {
  parse(yamlString) → AST
  validate(ast) → ValidationResult
}

// RegexEngine.js - Safe regex execution
class RegexEngine {
  compile(pattern) → SafeRegex
  execute(regex, input, timeout) → MatchResult
  // ReDoS protection with timeout
}

// DetectionEngine.js - Rule execution
class DetectionEngine {
  evaluate(ast, logs) → DetectionResult
}
```

---

## Phase 3: Scenario Schema & Log Sources

### 3.1 Scenario Schema

```javascript
{
  id: "L1-001",
  title: "The Hello World of Malware",
  level: 1,
  difficulty: 1, // 1-5 within level

  // Educational Metadata
  mitre: {
    tactic: "Execution",
    technique: "T1059.001",
    techniqueName: "PowerShell",
    url: "https://attack.mitre.org/techniques/T1059/001/"
  },
  realWorldReference: {
    incident: "SolarWinds SUNBURST",
    year: 2020,
    description: "Attackers used encoded PowerShell for C2 communication",
    sources: ["https://..."]
  },

  // Gameplay
  briefing: "...", // Sanitized HTML
  objective: "Detect encoded PowerShell execution",
  hints: [
    { cost: 50, content: "Look for the -enc or -EncodedCommand flag" },
    { cost: 100, content: "Filter on CommandLine|contains" },
    { cost: 200, content: "Full solution...", isSolution: true }
  ],

  // Log Data
  logSource: "process_creation", // or "network", "auth", "file", "registry"
  logs: [...],

  // Validation
  expectedDetections: [102, 105], // Log IDs that should match
  acceptableSolutions: [...], // Multiple valid approaches

  // Rewards
  baseReward: 150,
  bonusReward: 50, // For optimal solution
}
```

### 3.2 Log Source Types

| Log Source | Fields | Use Cases |
|------------|--------|-----------|
| **Process Creation** | Image, CommandLine, ParentImage, User, IntegrityLevel | Malware execution, LOLBins |
| **Network Connection** | SourceIP, DestIP, DestPort, Protocol, ProcessName | C2, Data exfil, Lateral movement |
| **Authentication** | TargetUser, LogonType, SourceIP, Status, FailureReason | Brute force, Pass-the-hash |
| **File System** | TargetFilename, Operation, ProcessName, Hash | Ransomware, Webshells |
| **Registry** | TargetKey, ValueName, Operation, ProcessName | Persistence, Defense evasion |
| **DNS** | QueryName, QueryType, ResponseCode, ProcessName | C2 beaconing, DNS tunneling |
| **PowerShell** | ScriptBlockText, ScriptPath, CommandInvocation | Script-based attacks |

---

## Phase 4: 75 Scenarios Overview

### Level 1: Junior Analyst (25 Scenarios)
Focus: Basic pattern matching, single log source, clear indicators

| # | Title | MITRE | Log Source | Real-World Reference |
|---|-------|-------|------------|---------------------|
| 1 | Encoded PowerShell | T1059.001 | Process | Multiple APTs |
| 2 | Whoami Reconnaissance | T1033 | Process | Post-exploitation standard |
| 3 | Shadow Copy Deletion | T1490 | Process | Ransomware (Ryuk, REvil) |
| 4 | Certutil Download | T1105 | Process | APT41, FIN7 |
| 5 | Suspicious WMIC | T1047 | Process | Cobalt Strike, APT29 |
| 6 | Mshta Execution | T1218.005 | Process | Emotet, Qbot |
| 7 | Regsvr32 Abuse | T1218.010 | Process | Squiblydoo attack |
| 8 | Rundll32 LOLBin | T1218.011 | Process | Various APTs |
| 9 | BITSAdmin Transfer | T1197 | Process | APT40, Leviathan |
| 10 | Scheduled Task Creation | T1053.005 | Process | Persistence technique |
| 11 | Service Installation | T1543.003 | Process | Persistence technique |
| 12 | Net User Enumeration | T1087.001 | Process | Reconnaissance |
| 13 | Net Group Discovery | T1087.002 | Process | Domain recon |
| 14 | Ping Sweep | T1018 | Process | Network discovery |
| 15 | LSASS Memory Access | T1003.001 | Process | Mimikatz |
| 16 | Failed Login Brute Force | T1110.001 | Auth | Credential attacks |
| 17 | Pass-the-Hash Detection | T1550.002 | Auth | Lateral movement |
| 18 | RDP Brute Force | T1110.001 | Auth | External attacks |
| 19 | Suspicious DNS Query | T1071.004 | DNS | C2 communication |
| 20 | Known Bad IP Connection | T1071.001 | Network | C2 infrastructure |
| 21 | Data Exfil Large Transfer | T1048 | Network | Data theft |
| 22 | Hosts File Modification | T1565.001 | File | DNS hijacking |
| 23 | Web Shell Creation | T1505.003 | File | ProxyShell, Exchange attacks |
| 24 | Startup Folder Persistence | T1547.001 | File | Basic persistence |
| 25 | Registry Run Key | T1547.001 | Registry | Persistence |

### Level 2: Intermediate (25 Scenarios)
Focus: Multiple conditions, filtering false positives, moderate complexity

| # | Title | MITRE | Log Source | Real-World Reference |
|---|-------|-------|------------|---------------------|
| 1 | Parent-Child Anomaly | T1059 | Process | Unusual process trees |
| 2 | Office Spawning Shell | T1204.002 | Process | Macro malware (Emotet) |
| 3 | Browser Spawning Shell | T1189 | Process | Drive-by download |
| 4 | LOLBAS Chain Detection | T1218 | Process | Living-off-the-land |
| 5 | PowerShell Download Cradle | T1059.001 | Process+PS | Cobalt Strike, Empire |
| 6 | WMI Persistence | T1546.003 | Process+WMI | APT29, DarkHotel |
| 7 | DLL Side Loading | T1574.002 | Process | APT41, Lazarus |
| 8 | Process Injection Indicators | T1055 | Process | Various malware |
| 9 | Token Manipulation | T1134 | Process | Privilege escalation |
| 10 | UAC Bypass Attempt | T1548.002 | Process | Many techniques |
| 11 | DCSync Attack | T1003.006 | Auth+Process | Mimikatz, BloodHound |
| 12 | Kerberoasting | T1558.003 | Auth | Active Directory attacks |
| 13 | AS-REP Roasting | T1558.004 | Auth | AD attacks |
| 14 | Golden Ticket Usage | T1558.001 | Auth | APT29, NotPetya |
| 15 | Lateral Movement via SMB | T1021.002 | Network | PsExec, wmiexec |
| 16 | DNS Tunneling | T1071.004 | DNS | Iodine, DNScat2 |
| 17 | Domain Fronting | T1090.004 | Network | APT29 |
| 18 | Beaconing Detection | T1071.001 | Network | C2 patterns |
| 19 | BITS Persistence | T1197 | Process+File | Background transfer abuse |
| 20 | Timestomping | T1070.006 | File | Anti-forensics |
| 21 | Alternate Data Streams | T1564.004 | File | Data hiding |
| 22 | Event Log Clearing | T1070.001 | Process | Anti-forensics |
| 23 | Firewall Rule Manipulation | T1562.004 | Process | Defense evasion |
| 24 | Disable Windows Defender | T1562.001 | Process+Registry | Common malware behavior |
| 25 | AMSI Bypass Attempt | T1562.001 | PowerShell | Script-based attacks |

### Level 3: Advanced (25 Scenarios)
Focus: Multi-stage attacks, correlation, complex regex, low false positives

| # | Title | MITRE | Log Source | Real-World Reference |
|---|-------|-------|------------|---------------------|
| 1 | APT29 Cozy Bear Simulation | Multiple | Multi-source | SolarWinds |
| 2 | Ransomware Kill Chain | Multiple | Multi-source | Ryuk, Conti |
| 3 | Supply Chain Compromise | T1195.002 | Multi-source | SolarWinds, Kaseya |
| 4 | Exchange ProxyShell | T1190 | Multi-source | ProxyShell CVE-2021 |
| 5 | Log4Shell Exploitation | T1190 | Multi-source | Log4j CVE-2021-44228 |
| 6 | PrintNightmare | T1068 | Multi-source | CVE-2021-34527 |
| 7 | ZeroLogon Attack | T1068 | Auth+Network | CVE-2020-1472 |
| 8 | BlueKeep Attempt | T1210 | Network | CVE-2019-0708 |
| 9 | EternalBlue Detection | T1210 | Network | WannaCry, NotPetya |
| 10 | Cobalt Strike Beacon | Multiple | Multi-source | Most common C2 |
| 11 | Metasploit Meterpreter | Multiple | Multi-source | Pentest/attack tool |
| 12 | Empire Framework | T1059.001 | Multi-source | PowerShell Empire |
| 13 | Mimikatz Full Detection | T1003 | Multi-source | Credential theft |
| 14 | BloodHound Collection | T1087.002 | Multi-source | AD reconnaissance |
| 15 | Impacket Tools | Multiple | Multi-source | Python attack toolkit |
| 16 | PsExec Lateral Movement | T1570 | Multi-source | Sysinternals abuse |
| 17 | WMIExec Detection | T1047 | Multi-source | Impacket wmiexec |
| 18 | DCOM Lateral Movement | T1021.003 | Multi-source | Stealthy movement |
| 19 | Credential Dumping Chain | T1003 | Multi-source | Full attack sequence |
| 20 | Data Staging & Exfil | T1074+T1048 | Multi-source | Full exfil chain |
| 21 | Insider Threat Pattern | Multiple | Multi-source | Data theft behavior |
| 22 | Living Off The Land Full | Multiple | Multi-source | LOLBAS chain |
| 23 | Fileless Malware Chain | Multiple | Multi-source | Memory-only attacks |
| 24 | Domain Admin Compromise | Multiple | Multi-source | Full domain takeover |
| 25 | APT Full Simulation | Multiple | Multi-source | Complete attack lifecycle |

---

## Phase 5: Economy & Scoring System

### 5.1 Scoring Table

| Event | Points | Notes |
|-------|--------|-------|
| **Perfect Detection** | +150 base | All malicious caught, 0 FP |
| **Optimal Solution Bonus** | +50 | Uses best practice patterns |
| **First Try Bonus** | +25 | No failed attempts |
| **True Positive** | +10 each | Partial credit |
| **False Positive** | -25 each | Noisy rule penalty |
| **Missed Attack** | -50 each | Critical failure |
| **Syntax Error** | -10 | Encourages careful writing |
| **Hint (Basic)** | -50 | Field name hints |
| **Hint (Advanced)** | -100 | Partial rule structure |
| **Buy Solution** | -200 | Full solution, no XP |
| **Log Highlighter** | -75 | One-time per scenario |

### 5.2 Rank Progression

| Rank | Cases Required | Accuracy Required | Budget Threshold |
|------|---------------|-------------------|------------------|
| Junior Analyst | 0 | - | - |
| Analyst | 5 | 70% | 500 |
| Senior Analyst | 15 | 80% | 1500 |
| Detection Engineer | 30 | 85% | 3000 |
| Senior Engineer | 50 | 90% | 5000 |
| Principal Engineer | 75 | 95% | 7500 |

### 5.3 Accuracy Calculation

```javascript
accuracy = truePositives / (truePositives + falsePositives + missedAttacks) * 100

// Tracked per-session and lifetime
// Affects rank progression
// Displayed on profile and leaderboard
```

### 5.4 Attempt Limiting

- **3 attempts per scenario** before hint is required
- Failed attempts logged for analytics
- Retry after cooldown (or budget spend)

---

## Phase 6: Security Implementation (OWASP Top 10)

### 6.1 A03:2021 - Injection (XSS Prevention)

```javascript
// utils/sanitize.js
import DOMPurify from 'dompurify';

export const sanitizeHTML = (dirty) => {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['div', 'span', 'p', 'strong', 'code', 'h3', 'ul', 'li'],
    ALLOWED_ATTR: ['class']
  });
};

// No dangerouslySetInnerHTML for user content
// All briefings pre-sanitized at build time
```

### 6.2 A01:2021 - Broken Access Control

```javascript
// Firestore Security Rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only access their own data
    match /users/{userId}/{document=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    // Leaderboard is read-only for all, write only via Cloud Function
    match /leaderboard/{entry} {
      allow read: if true;
      allow write: if false; // Server-side only
    }
  }
}
```

### 6.3 A04:2021 - Insecure Design (Anti-Cheat)

```javascript
// Server-side score validation via Cloud Function
// Client submits: { scenarioId, userRule, detectionResults }
// Server re-runs detection engine to verify
// Prevents score manipulation via DevTools
```

### 6.4 A05:2021 - Security Misconfiguration

```javascript
// .env (never committed)
VITE_FIREBASE_API_KEY=xxx
VITE_FIREBASE_AUTH_DOMAIN=xxx
// etc.

// .env.example (committed, no values)
VITE_FIREBASE_API_KEY=
VITE_FIREBASE_AUTH_DOMAIN=
```

### 6.5 A07:2021 - Authentication Failures

```javascript
// Rate limiting on rule submissions
const RATE_LIMIT = {
  maxAttempts: 10,
  windowMs: 60000, // 1 minute
};

// Session management handled by Firebase Auth
// Anonymous sessions have limited capabilities
```

### 6.6 Regex DoS Prevention (ReDoS)

```javascript
// RegexEngine.js
const REGEX_TIMEOUT_MS = 1000;
const MAX_REGEX_LENGTH = 500;

export const safeRegexTest = (pattern, input) => {
  if (pattern.length > MAX_REGEX_LENGTH) {
    throw new Error('Regex pattern too long');
  }

  // Use vm2 or similar for sandboxed execution
  // Or Web Worker with timeout
  const worker = new Worker('regexWorker.js');
  const timeoutId = setTimeout(() => worker.terminate(), REGEX_TIMEOUT_MS);

  return new Promise((resolve, reject) => {
    worker.onmessage = (e) => {
      clearTimeout(timeoutId);
      resolve(e.data);
    };
    worker.onerror = reject;
    worker.postMessage({ pattern, input });
  });
};
```

---

## Phase 7: Implementation Order

### Week 1: Foundation
- [ ] Initialize Vite project with dependencies
- [ ] Set up Tailwind configuration
- [ ] Create project structure
- [ ] Implement base UI components
- [ ] Port existing views to component structure

### Week 2: Engine
- [ ] Build SigmaParser with full modifier support
- [ ] Implement RegexEngine with safety measures
- [ ] Create DetectionEngine
- [ ] Write comprehensive unit tests for parser

### Week 3: Scenarios (Part 1)
- [ ] Define final scenario schema
- [ ] Create Level 1 scenarios (25)
- [ ] Create log templates for each source type
- [ ] Test scenarios for solvability

### Week 4: Scenarios (Part 2)
- [ ] Create Level 2 scenarios (25)
- [ ] Create Level 3 scenarios (25)
- [ ] Balance difficulty curve
- [ ] QA all scenarios

### Week 5: Economy & Progression
- [ ] Implement scoring system
- [ ] Add rank progression logic
- [ ] Implement hint purchasing
- [ ] Add attempt limiting
- [ ] Accuracy tracking

### Week 6: Polish & Security
- [ ] Security audit (OWASP checklist)
- [ ] Performance optimization
- [ ] Mobile responsiveness
- [ ] Final QA
- [ ] Documentation

---

## Deliverables

1. **Fully modular React application** with Vite
2. **75 unique detection scenarios** mapped to MITRE ATT&CK
3. **Enhanced Sigma parser** with regex support
4. **Comprehensive economy system** with consequences
5. **6-tier rank progression** based on performance
6. **OWASP-compliant security** throughout
7. **Production-ready documentation**

---

## Approval Checklist

Please confirm:

- [ ] Project structure approved
- [ ] Scenario list (75) approved
- [ ] Economy/scoring system approved
- [ ] Security approach approved
- [ ] Ready to begin implementation

---

*Plan Version: 1.0*
*Created: 2026-01-05*
