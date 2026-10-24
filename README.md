# AI Threat Intelligence Monitoring Assistant — ZeroDay

A hackathon project exploring cybersecurity solutions for ZeroDay vulnerabilities. The app captures a comma-separated software stack and searches public security advisories with TinyFish Search + Fetch. Search results include source links, fetched page content, and fetch times. CVE extraction, stack matching, and risk scoring are planned for later phases.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Create `.streamlit/secrets.toml` with your TinyFish key:

```toml
TINYFISH_API_KEY = "paste-your-key-here"
```

Enter a small demo stack such as `nginx, WordPress`, save it, and click **Search advisories**. Keep the API key out of source code and do not commit `secrets.toml`.
