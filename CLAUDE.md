# STIG Assist — Claude Code Context

## What This Is
STIG Assist is a web application that helps DevSecOps teams apply DISA STIGs to Docker containers at scale.

## Running the App
```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here
python app.py
```
Then open http://localhost:5000 in your browser.

## Project Structure
- `app.py` — Flask backend with Anthropic API routes
- `static/index.html` — Single-page frontend (Tailwind CSS, vanilla JS)
- `prompts/stig_analyze.txt` — System prompt for STIG analysis (editable without code changes)
- `sample_data/sample_findings.xml` — Sample Nessus/SCAP XML for testing
- `tests/test_app.py` — Flask route tests

## Key Design Decisions
- No build step — runs with `python app.py`
- Session state only, no database
- Prompts are in `/prompts/` so they can be tuned without touching Python code
- API key from `ANTHROPIC_API_KEY` env var — never hardcoded

## Claude Model
Uses `claude-sonnet-4-20250514` for all AI calls.

## Severity Color Coding
- CAT I = red (#ef4444)
- CAT II = amber (#f59e0b)
- CAT III = blue (#3b82f6)
