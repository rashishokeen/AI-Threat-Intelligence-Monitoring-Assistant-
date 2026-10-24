# ZeroDay Threat Intelligence Monitor

## Phase 1 and 2 scaffold

The app captures a comma-separated software stack and establishes the shared finding model in `src/models.py`. Phase 2 adds TinyFish Search + Fetch and displays the result links, fetched page content, and fetch time. CVE extraction and risk scoring belong to later phases.

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
