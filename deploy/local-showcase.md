# Local OWASP Top 10:2025 showcase

Start from the repository root with `.venv/bin/python demo_web.py`, then open http://127.0.0.1:8765. Stop with Ctrl+C. The launcher binds only to loopback, clears inherited application credentials and scanner overrides, and never loads `.env` or imports the webhook application. No auto-start or public tunnel is configured.

## Ten examples, with honest evidence

The category mapping follows the [official OWASP Top 10:2025](https://top10.owasp.org/2025/), with a direct category source linked in each example. Categories overlap; each fixture illustrates one specific issue, not the whole category.

| Category | Example | Evidence offered |
|---|---|---|
| [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) | Invoice ownership | Real synthetic behavioral assertions |
| [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/) | Debug responses | Real Semgrep pattern scan |
| [A03:2025 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | Dependency release gates | Real synthetic behavioral assertions |
| [A04:2025 Cryptographic Failures](https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/) | TLS certificate verification | Real Semgrep pattern scan |
| [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) | SQL parameter binding | Real Semgrep pattern scan |
| [A06:2025 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/) | One coupon per customer | Real synthetic behavioral assertions |
| [A07:2025 Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/) | Session rotation at login | Real synthetic behavioral assertions |
| [A08:2025 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/) | Safe YAML deserialization | Real Semgrep pattern scan |
| [A09:2025 Security Logging and Alerting Failures](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | Observable access denials | Real synthetic behavioral assertions |
| [A10:2025 Mishandling of Exceptional Conditions](https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/) | Fail closed on timeout | Real synthetic behavioral assertions |

## Walkthrough

1. Choose a category and inspect the visible original source, risk explanation and official reference. Specific vulnerable lines carry a red accent and a Vulnerable label; proposed mitigation lines carry a green accent and a Fix label. The labels also appear on matching changed lines in the diff. These teaching annotations do not certify other lines as safe, and manual examples are explicitly illustrative.
2. Run the local workflow. Four examples run Semgrep: vulnerable versions produce one finding, fixed versions produce none under the narrow demo rules. Select a finding to highlight its actual line.
3. Six examples skip Semgrep and run a distinct **Behavioral test** stage. Vulnerable fixtures fail real security assertions; fixed fixtures pass the scoped synthetic lab assertions. The evidence panel lists each assertion, its observed result and measured duration. A completed harness with a failed security assertion is an expected demonstration, distinct from a harness error.
4. Select the proposed fix and inspect the diff. Supporting services in access/session/store/audit/pipeline examples are implemented as synthetic adapters in the lab harness. Results prove only the stated conditions against those adapters. Real service integrations still need validation.
5. Rerun or select previous runs. Changing scenario/version resets the active result; history exists only in this browser page.

## Boundaries and limitations

Source loading, scan results, durations and activity logs reflect actual local work. GitHub repository/workflow context is simulated. No GitHub Check, comment or repository change is sent. No artificial delays are added.

Four static-scanning fixtures are read only. Six authored, hash-pinned behavioral fixtures execute in isolated Python child processes with synthetic in-memory services. No fixture performs a network request, dependency installation, real database operation or external alert. Only a server-owned allowlist of bundled files is accepted, with cross-origin requests rejected and text-only rendering under CSP. Legacy command-injection endpoints/rule remain for compatibility but are not an eleventh category in the selector. Production rules are unchanged.

The four static rules cover literal FastAPI debug configuration, selected Requests verification arguments, SQL concatenation and selected YAML loaders. They do not cover each category comprehensively or prove a fixed application secure. The six behavioral examples run actual controlled assertions; real deployment integrations and broader category coverage remain unverified. A failed scanner produces an error, never a clean verdict.

The local process is not an OS sandbox. Production still requires supported remediation of five scanner dependency advisories, actual Linux/rootless-container validation, and authorized live GitHub integration testing.

## Validation

At the showcase checkpoint, `make check` passed **185 tests**, followed by real vulnerable/clean CLI fixture scans. JavaScript syntax and `git diff --check` passed.

`tests/browser/owasp_demo.cjs` exercises all ten examples × both variants at desktop (1366px) and mobile (390px), exact rendered source, targeted red/green labels, inert HTML rendering, diffs before/after results, actual finding annotations, behavioral assertion states, history/reset, failed requests/retry, keyboard navigation and JavaScript errors. All passed against the live loopback server. It uses isolated headless Playwright, never the desktop Chrome profile. With Playwright already available to Node and its browser installed, run `node tests/browser/owasp_demo.cjs`; optionally set `OUT` to an existing screenshot directory. No new installation is required by the application itself.

## Historical outcome wording checkpoint (superseded by behavioral execution)

A live check of all ten fixed examples returned four scanner successes (A02, A04, A05, A08) and six manual-review responses. The reported all-ten manual outcome was not reproduced; no cache cause was established. Generic wording was replaced with **Scan passed — no findings for this rule**, **Scan found a vulnerable pattern**, and **Manual review required — not scanned**. Review method text is explicitly separate from the result, manual fixed selections say verification is still needed, and history retains the correct outcome. The browser regression asserts these exact labels for every scenario/version and verifies reset/history, desktop/mobile and error recovery. Red/green line annotations are preserved.

## Behavioral completion

The previous six review-only outcomes came from deliberately having no executable harness for those examples. That functional gap is now closed: all six execute their authored fixture with synthetic adapters, and all fixed examples have actual scoped passing outcomes. See [behavioral-lab.md](behavioral-lab.md) for exact assertions, safeguards and limits. Current labels distinguish **Scan passed — no findings for this rule** from **Behavioral tests passed — scoped assertions**.

## Consistent result presentation

Every successful workflow now says **Checks passed**; failed assertions/findings say **Checks failed**, and incomplete execution says **Check error**. The same primary outcome appears in the summary and history. A secondary **Static analysis** or **Behavioral tests** label gives the actual finding count or passed/total assertions, with scope and evidence below. Pipeline jobs retain uniform Passed/Failed/Error/Not run states. All twenty variants passed desktop/mobile rendered regression checks after this presentation change.
