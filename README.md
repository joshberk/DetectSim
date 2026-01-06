# DetectSim

> Master the art of the Blue Team.

A gamified "Cyber Range" where you learn to write high-fidelity detection rules, hunt threats, and avoid false positives.

## About The Project

DetectSim bridges the gap between theoretical cybersecurity knowledge and practical application. While most CTFs focus on breaking things (Red Team), this platform focuses on catching the breakers (Blue Team).

Players act as SOC Analysts investigating real-world scenarios. The goal isn't just to find the "evil" log—it's to write a Sigma-style detection rule that catches the attacker without flagging legitimate user activity (False Positives).

## Key Features

- **Simulated SIEM Interface**: Toggle between parsed JSON objects and raw Syslog strings to simulate real-world analysis
- **Custom Sigma Parser**: An in-browser YAML detection engine supporting selection, condition, and list-based logic with full regex support
- **50 Detection Scenarios**: Across 3 difficulty levels (Junior, Intermediate, Advanced)
- **MITRE ATT&CK Mapping**: Every scenario maps to real-world tactics and techniques
- **Real-World References**: Learn from actual incidents (Emotet, SolarWinds, Log4Shell, etc.)

### Accuracy Mechanics

- **True Positives**: Catching the malware earns budget
- **False Positives**: Flagging the CEO's benign PowerShell script deducts points
- **Missed Attacks**: Letting threats slip through damages reputation

### Progression System

- **Career Ranks**: Progress from Intern to CISO based on cases solved and accuracy
- **Economy System**: Earn "Budget" to unlock tiered hints (Basic → Advanced → Solution)
- **Failure Consequences**: Poor detections cost budget and limit attempts

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18 + Vite |
| Styling | Tailwind CSS (Dark mode) |
| Icons | Lucide React |
| Security | DOMPurify (XSS prevention) |
| Backend | Firebase Firestore & Anonymous Auth |
| Fallback | localStorage (offline support) |

## Getting Started

### Prerequisites

- Node.js 18+ & npm
- A Firebase Project (optional, works offline with localStorage)

### Installation

```bash
# Clone the repository
git clone https://github.com/joshberk/DetectSim.git
cd DetectSim

# Install dependencies
npm install

# Start development server
npm run dev
```

### Firebase Configuration (Optional)

Create a `.env` file in the root directory:

```env
VITE_FIREBASE_API_KEY=your_api_key
VITE_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_project.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
VITE_FIREBASE_APP_ID=your_app_id
```

## How to Play

1. **Briefing**: Read the Incident Report and understand the threat
2. **Analysis**: Scan the Log Stream. Look for suspicious binaries (`whoami.exe`, `vssadmin.exe`) or flags (`-EncodedCommand`)
3. **Engineering**: Write a detection rule in the Editor

```yaml
detection:
  selection:
    Image|endswith: 'powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
```

4. **Deploy**: Click "Deploy Rule." If your logic catches threats without false positives, you earn Budget and rank up

### Supported Sigma Modifiers

| Modifier | Description |
|----------|-------------|
| `contains` | Substring match (case-insensitive) |
| `endswith` | Suffix match |
| `startswith` | Prefix match |
| `re` | Regular expression pattern |
| `base64` | Base64-encoded value match |
| `cidr` | IP range matching |

## Scenario Levels

| Level | Difficulty | Scenarios | Focus |
|-------|------------|-----------|-------|
| 1 | Junior | 17 | Single indicators, basic patterns |
| 2 | Intermediate | 17 | Multiple conditions, evasion techniques |
| 3 | Advanced | 16 | Multi-stage attacks, correlation |

## Roadmap

- [x] Custom Sigma Parser with modifiers
- [x] Regex support with ReDoS protection
- [x] 50 detection scenarios with MITRE mapping
- [x] Career progression and economy system
- [x] Persistence (Firebase + localStorage fallback)
- [ ] Global Leaderboard with Firebase sync
- [ ] Network Logs: Firewall & PCAP analysis scenarios
- [ ] Multi-stage Attacks: Correlation across multiple log sources
- [ ] Custom scenario builder

## License

Distributed under the MIT License. See `LICENSE` for more information.
