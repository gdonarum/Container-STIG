# STIG Assist

A web application for applying DISA STIGs to Docker containers at scale.

## Quick Start

### Option 1: GitHub Pages (no backend required)

Visit the hosted version and enter your own Anthropic API key:
- **URL**: `https://<your-username>.github.io/Container-STIG/`

Your API key is stored only in your browser (localStorage) and sent directly to Anthropic.

### Option 2: Run Locally (static site)

```bash
cd static
python -m http.server 5000
# or: npx serve -l 5000
```

Open http://localhost:5000, enter your API key, and use the app.

### Option 3: Run with Flask Backend

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
python app.py
```

Open http://localhost:5000 in your browser.

### Option 4: Run via Docker

```bash
docker run -p 5000:5000 -e ANTHROPIC_API_KEY=sk-ant-... ghcr.io/gdonarum/container-stig:latest
```

Open http://localhost:5000. The image is built automatically on each push to `main`.

## Features

**Tab 1 — Findings Analyzer**
Paste Nessus/SCAP XML or plain-text findings. Get AI-analyzed results grouped by severity (CAT I/II/III) with plain-English explanations, remediation steps, Dockerfile fixes, and a generated hardened Dockerfile.

**Tab 2 — Dockerfile Hardener**
Paste an existing Dockerfile and select a target STIG/SRG. Get a hardened version with inline comments and a side-by-side diff.

**Tab 3 — POA&M Helper**
Paste findings and get draft Plan of Action & Milestones entries with milestone language ready for human completion dates.

## Hardened Image Pipeline

Generate STIG-hardened base images via GitHub Actions:

1. Add `ANTHROPIC_API_KEY` to repo secrets
2. Go to Actions → "Harden Base Images"
3. Select a base image (ubuntu, alpine, ubi9) and run
4. Pull the hardened image:
   ```bash
   docker pull ghcr.io/<owner>/hardened-bases:ubuntu-22.04-hardened
   ```

## Testing

```bash
ANTHROPIC_API_KEY=test-key python -m pytest tests/ -v
```

## Requirements

- Python 3.9+ (for Flask backend or tests)
- Anthropic API key (Claude claude-sonnet-4-20250514)
- No other external services required

## Sample Data

Load the sample Nessus XML via the "Load Sample" button in the Findings Analyzer tab, or find it at `sample_data/sample_findings.xml`.

## Configuration

The system prompt for STIG analysis is in `prompts/stig_analyze.txt` — edit this file to tune AI behavior without touching Python code.

## Security Notes

- **Client-side mode**: Your API key is stored in localStorage (if "Remember" is checked) and sent directly to Anthropic over HTTPS. It never touches any server.
- **GitHub Actions**: The `ANTHROPIC_API_KEY` secret is encrypted and never exposed in logs.

## License

PolyForm Noncommercial License 1.0.0. Commercial use requires a separate written agreement.
