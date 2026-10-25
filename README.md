# AI Threat Intelligence Monitoring Assistant — ZeroDay

A hackathon project exploring cybersecurity solutions for ZeroDay vulnerabilities. The app captures a comma-separated software stack, searches and fetches public security advisories with TinyFish, extracts source-backed advisory details with Gemini, compares advisory product names with the saved stack, and scores findings when the evidence is complete.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Create `.streamlit/secrets.toml` with your TinyFish and Gemini API keys:

```toml
TINYFISH_API_KEY = "paste-your-key-here"
LLM_API_KEY = "paste-your-Gemini-key-here"
LLM_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
LLM_MODEL = "gemini-3.6-flash"
```

Enter a small demo stack such as `nginx, WordPress`, save it, and click **Search advisories**. Use **Extract advisory details** on a fetched page to extract CVE facts, see product-name matches, and view risk scores when evidence is complete. The match is not an installed-version check.

## Risk score and confidence

The 0–10 risk formula is `40% CVSS severity + 25% known-exploited status + 25% stack match + 10% recency`. Each component is 0–10; known exploited maps to 10 for yes and 0 for no. Recency maps to 10 (0–30 days), 8 (31–90), 6 (91–180), 4 (181–365), 2 (366–730), and 0 (older). When CVSS is absent, a stated severity category uses a clearly disclosed representative estimate. If one or more factors are missing, the app shows a provisional, Low-confidence score using the available factors and their weights normalized to 0–10. With fewer than two supported factors or no verified source quote, it shows **Not enough evidence** instead.

Confidence uses distinct verified source URLs: High requires 3 sources including 2 identified primary sources; Medium requires 2 including 1 primary; otherwise it is Low. This is an MVP evidence heuristic, not a statistical probability. Gemini's free tier has model-specific limits; check your quota in Google AI Studio. Keep API keys out of source code and do not commit `secrets.toml`.
