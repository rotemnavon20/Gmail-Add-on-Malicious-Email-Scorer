# Malicious Email Scorer

## Overview
Malicious Email Scorer is a custom Gmail Add-on designed to evaluate incoming emails for phishing attempts and malicious content. The system combines deterministic heuristic scoring with deep semantic AI analysis, providing a real-time threat assessment directly within the Gmail UI.

## Architecture
**Frontend (Google Apps Script):** Acts as the user interface inside the Gmail sidebar. It extracts email metadata (sender, subject, body, and authentication headers), communicates with the backend API, and provides interactive feedback buttons (`Safe` / `Malicious`).

**Backend (Node.js & TypeScript):** Runs locally and processes email data. It applies heuristic threat scoring, integrates with VirusTotal and OpenAI APIs, and manages persistent local storage for trusted senders based on user feedback.

## Key Features
- **Hybrid Threat Scoring:** Combines rule-based heuristics (domain verification, URL analysis) with deep LLM semantic analysis (triggered dynamically for medium-risk emails).
- **Interactive User Feedback & Whitelisting:** Users can mark emails as "Safe" or "Malicious" via the UI. Marking a sender as "Safe" automatically saves them to a persistent `trusted-senders.json` file, mitigating future risk scores (-25 points).
- **Smart URL & Subdomain Logic:** Detects abusive shortened URLs (for example bit.ly) and unencrypted HTTP links while explicitly exempting legitimate corporate domains (for example google.com) to prevent false positives.
- **VirusTotal Integration:** Inspects links for malicious reputations, effectively handling API rate limits and ignoring unverified links.
- **Detailed Reasoning:** Generates clear threat verdicts with color-coded UI indicators and appends specific `[AI Analysis]` insights when the LLM is triggered.

## Prerequisites
- [Node.js](https://nodejs.org/) 
- [ngrok](https://ngrok.com/) (for exposing the local backend)
- [clasp](https://github.com/google/clasp) (Command Line Apps Script Projects)
- OpenAI API Key & VirusTotal API Key

## Setup & Installation

### 1. Backend Setup
1. Navigate to the `backend` directory.
2. Install dependencies:
   npm install
3. Create a .env file in the backend directory with your API keys:
    PORT=3000
    OPENAI_API_KEY=your_openai_api_key_here
    VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
4. Start the local development server (runs with hot-reloading via tsx watch):
    npm run dev

### 2. Expose the Backend
1. Open a new terminal window and run ngrok to expose your local server to the internet:
    ngrok http 3000
2. Copy the generated https://... Forwarding URL from the ngrok terminal output.

### 3. Frontend Setup
1. Open Code.ts in your frontend directory.
2. Update the backendUrl variable with your ngrok forwarding URL, pointing to the analyze endpoint:
    const backendUrl = '[https://your-ngrok-url.ngrok-free.dev/api/analyze]'
3. Push the updated code to Google Apps Script using clasp:
    clasp push

## Scoring Logic & Thresholds
1. Known Sender / Trusted Mitigation:
- Recognized senders from local communication history or the persistent trusted-senders.json file reduce the risk score by -25 points.
- Legitimate service footprints (e.g., Spark Hire, Greenhouse) reduce the risk score by -60 points.

2. Sender & Domain Penalties:
- Invalid sender format: +50 points.
- High-risk financial/security display name combined with a generic domain: +35 points.
- Unrecognized/unverified sender domain: +15 points.
- High-risk TLDs (e.g., .xyz, .click): +40 points.
- Brand impersonation (typosquatting on targeted brands): +60 points.

3. Content & Phrasing Penalties:
- Urgent or coercive language in the subject: +30 points.
- Suspicious phishing phrasing or machine-translation patterns in the body: +25 points.
- Combination of urgent language and sensitive financial requests: +25 points.

4. URL & Link Analysis Penalties:
- URL mismatch (anchor text differs from target domain): +50 points.
- Links pointing directly to a raw IP address: +40 points.
- Unencrypted HTTP clickable links: +40 points.
- Generic abusive URL shorteners: +30 points.
- Links flagged explicitly as malicious by VirusTotal: overrides score directly to 100 (Critical).

5. AI Deep Analysis (LLM Integration):
- Automatically triggered for emails with a preliminary score in the gray area (45-65).
- The AI evaluates semantic context, social engineering tactics, and phishing vectors, adjusting the final score and appending a detailed [AI Analysis] note to the reasoning.

6. Threat Verdicts:
- Scores range from 0 to 100, categorized into clear verdicts with color-coded UI indicators:
- Safe (Score < 30, Green)
- Caution (Score 30–49, Yellow/Orange)
- Suspicious (Score 50–69, Orange)
- Highly Suspicious (Score ≥ 70, Red)

## Usage
1. Open Gmail and click on any incoming email.
2. Open the Malicious Email Scorer add-on from the right-hand Gmail sidebar.
3. Review the calculated Threat Level, Risk Score, Verdict, and detailed Analysis Reasoning directly in the card interface. Use the "Safe" or "Malicious" buttons to feed data back into your local persistent cache.    