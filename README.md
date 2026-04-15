# DetectSim

Most security training puts you on offense — exploit this box, crack that hash. DetectSim flips it. You're the analyst on the other side, staring at a live log stream, trying to write a rule that catches the attacker without nuking your alert queue with noise.

It's a browser-based detection engineering playground built around [Sigma](https://sigmahq.io/) rules. Think of it as a coding challenge platform, but for Blue Team.

---

## What it actually is

You get an incident briefing, a stream of logs (some malicious, most benign), and an editor. Your job is to write a detection rule that catches the bad stuff without triggering on the legitimate activity. Hit "Deploy" and the engine runs your rule against the full log set in real time.

Get it right and you earn budget, climb the rank ladder, and unlock harder scenarios. Flag the CEO's PowerShell or miss the C2 beacon and you pay for it.

The rule syntax follows Sigma — the open standard used by real SOC teams. If you've never written a Sigma rule before, that's the point. You'll pick it up fast.

---

## Features

**50 scenarios across 3 difficulty tiers** — Junior scenarios focus on single obvious indicators (encoded PowerShell, suspicious process names). Intermediate introduces evasion and false positive traps. Advanced gets into multi-stage attacks and correlation logic.

**Custom Sigma parser running entirely in-browser** — supports `contains`, `endswith`, `startswith`, `re` (regex with ReDoS protection), `base64`, `cidr`, `gt/gte/lt/lte`, and list-based OR logic. No backend needed.

**CodeMirror editor** — proper YAML syntax highlighting, line numbers, bracket matching. Writing detection rules in a plain textarea felt wrong so it got replaced.

**MITRE ATT&CK coverage heatmap** — the Statistics page shows which tactics you've covered across all 50 scenarios. Each tile fills in as you complete scenarios in that tactic category.

**Economy system** — you start with a budget and spend it on hints (tiered: nudge → detailed hint → full solution). False positives and missed attacks cost budget. It makes you think twice before deploying a noisy rule.

**Rank progression** — Junior Analyst → Analyst → Senior Analyst → Detection Engineer → Senior Engineer → Principal Engineer. Rank gates are based on cases solved, accuracy, and budget earned.

**Achievement system** — 24 achievements across categories like accuracy milestones, speed runs, and streaks. They fire as toasts and are tracked in a dedicated view.

**Rank-up ceremony** — when you hit a new rank a full-screen overlay fires with an animated badge reveal. Small thing but it feels good.

**Leaderboard** — score tracking with Firebase sync (or localStorage if you're running offline).

---

## Stack

React 18, Vite, Tailwind CSS, Firebase (Firestore + anonymous auth), CodeMirror 6, DOMPurify. Runs entirely in the browser — Firebase is optional, everything falls back to localStorage.

---

## Running it locally

You need **Node.js 18 or higher**. Check with `node -v` if you're not sure.

```bash
git clone https://github.com/yourusername/DetectSim.git
cd DetectSim
npm install
npm run dev
```

Open **http://localhost:3000** in your browser. That's all — no database, no accounts, no API keys required to get started. Progress is saved to `localStorage` so it survives page refreshes.

### Firebase setup (optional)

Without Firebase you lose the leaderboard and cross-device sync, but everything else works fine. If you want those features:

1. Create a project at [console.firebase.google.com](https://console.firebase.google.com)
2. Add a Web app — Firebase will show you the config object
3. Enable **Firestore** (start in test mode is fine) and **Anonymous Authentication** under Authentication → Sign-in methods
4. Create a `.env.local` file in the project root and paste your values:

```env
VITE_FIREBASE_API_KEY=AIza...
VITE_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your-project-id
VITE_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=123456789
VITE_FIREBASE_APP_ID=1:123456789:web:abc123
```

Restart the dev server after adding the file.

### Building for production

```bash
npm run build       # outputs to /dist
npm run preview     # serves the build locally to check it before deploying
```

The build is a fully static bundle — drop the `/dist` folder on any static host (Vercel, Netlify, GitHub Pages, S3, etc.).

---

## Writing rules

The editor uses a subset of Sigma syntax focused on the `detection` block:

```yaml
detection:
  selection:
    Image|endswith: 'powershell.exe'
    CommandLine|contains|all:
      - '-enc'
      - '-nop'
  condition: selection
```

Multiple values in a list are OR'd together by default. Use `|all` to require all of them. Combine selections with `and`, `or`, `not` in the condition. That covers most real-world detection logic.

---

## Scenario breakdown

| Level | Name | Count | What you're dealing with |
|-------|------|-------|--------------------------|
| 1 | Junior Analyst | 17 | Encoded commands, suspicious binaries, brute force patterns |
| 2 | Intermediate | 17 | Evasion, legitimate tool abuse (LOLBins), FP traps |
| 3 | Advanced | 16 | Multi-stage attacks, lateral movement, credential theft chains |

Every scenario maps to a real MITRE ATT&CK technique and references actual incidents where relevant (Emotet, SolarWinds, Log4Shell, etc.).

---

## What's next

- [ ] Multi-source correlation — writing rules that span process + network + registry logs
- [ ] Custom scenario builder — let users author and share their own log sets
- [ ] Network/PCAP scenarios — firewall logs, DNS tunneling, beaconing patterns
- [ ] Multiplayer — race another analyst to the correct rule

---

## License

MIT
