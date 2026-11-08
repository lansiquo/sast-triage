##### Dev setup
1. Use Python 3.11–3.13 (`.python-version` pins 3.12; CI runs 3.12).
2. Create a virtualenv, install the dependencies and run the checks:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   python -m pip install -r requirements.txt
   make check        # offline tests, then the demo
   ```
3. Keep `make check` passing. CI runs it on every pull request and push to main.
