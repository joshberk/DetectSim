🛡️ DetectSim
Master the art of the Blue Team. > A gamified "Cyber Range" where you learn to write high-fidelity detection rules, hunt threats, and avoid false positives.

📖 About The Project
Detection Engineering RPG bridges the gap between theoretical cybersecurity knowledge and practical application. While most CTFs focus on breaking things (Red Team), this platform focuses on catching the breakers (Blue Team).
Players act as SOC Analysts investigating real-world scenarios. The goal isn't just to find the "evil" log—it's to write a Sigma-style detection rule that catches the attacker without flagging legitimate user activity (False Positives).

🎮 Key Features
Simulated SIEM Interface: Toggle between parsed JSON objects and raw Syslog strings to simulate real-world analysis.Custom Sigma Parser: An in-browser YAML detection engine that supports selection, condition, and list-based logic.

Accuracy Mechanics:
True Positives: Catching the malware.False Positives: Flagging the CEO's benign PowerShell script (deducts points!).Career Progression: Rank up from Junior Analyst to Senior Engineer based on cases solved.Economy System: Earn "Budget" to unlock hints and templates.Global Leaderboard: Compete with other analysts via real-time Firebase syncing.

⚡Tech Stack
Frontend: React.js (Single File Component structure for portability)
Styling: Tailwind CSS (Dark mode focused)
Icons: Lucide React
Backend / Persistence: Firebase Firestore & Authentication (Anonymous Auth)

🚀 Getting Started

Prerequisites
Node.js & npm
A Firebase Project (Free Tier)Installation


🕹️ How to Play
Briefing: Read the Incident Report (Intel).Analysis: Scan the Log Stream. Look for suspicious binaries (whoami.exe, vssadmin.exe) or flags (-EncodedCommand).Engineering: Write a detection rule in the Editor.
detection:
  selection:
    Image|endswith: 'powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
Deploy: Click "Deploy Rule." If your logic is sound, you earn Budget and Rank XP.

🗺️ Roadmap
[x] Basic Sigma Parser (Strings/Lists)
[x] Persistence & Leaderboards[ ] Network Logs: Firewall & PCAP analysis scenarios.
[ ] Regex Support: Advanced pattern matching.
[ ] Multi-stage Attacks: Scenarios requiring correlation across multiple log sources.

📄 License
Distributed under the MIT License. See LICENSE for more information.
