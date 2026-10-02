# Local privacy playground

## First run

Follow the [README quickstart](../README.md#try-it-locally) to clone the project,
create a virtual environment, and install only the runtime dependencies. The
playground needs no API key, provider account, Docker, or NER model.

From the project directory, start `.venv/bin/cloakspan playground` on
macOS/Linux, or `.\.venv\Scripts\cloakspan.exe playground` in Windows PowerShell.
Open the printed loopback URL and enter the session access code from the
terminal. Choose **Email address**, then **Inspect locally**. Under the bundled default
policy, the decision is `TRANSFORM` and the projected request replaces
`alex@example.com` with an `EMAIL_ADDRESS` token. The credential sample is
blocked with no projected outbound text. Stop the app with **Ctrl+C**.

## Settings and behavior

Run `cloakspan playground` and open the printed `http://127.0.0.1:8765` address. Enter the fresh session access code from the terminal. Use `cloakspan playground --port 8766` when the default port is busy. Both `cloakspan` and `secure-ai-gateway` keep their no-argument server behavior.

The page previews one text message at a time. It uses the inherited `SAG_POLICY_PATH`, `SAG_FILTERS_PATH`, detector settings, and `SAG_LOCAL_ROUTING`. It does not load a `.env` file automatically. The application selector contains `default` and the application names used in policy rules; it simulates policy context without testing production authentication. Synthetic examples are illustrative under the bundled policy; operator rules can change the result.

The preview shows resolved detections, the policy rule and any local-routing override, the logical destination, and the projected text and model. **No provider is contacted.** A `BLOCK` decision is shown with no outbound text. `ALLOW` keeps the original text unchanged even when a detector found a value. `TRANSFORM` and `ROUTE_LOCAL` use the gateway's transformation logic. Preview tokens are minted with fresh keys for each inspection, so they can differ from production tokens. No response restoration is simulated.

The local app binds only to `127.0.0.1`. It serves bundled assets offline, has no external frontend dependencies, and does not write input, output, tokens, or history to disk or browser storage. The code exists only in page memory; reloading locks the page. Clear removes displayed text and results, but cannot guarantee forensic erasure from Python or browser memory or operating-system swap. Copying projected text is an explicit action.

The worker loads an enabled local NER model before serving requests. A missing or unusable enabled model prevents inspection. With NER disabled, the page warns that contextual coverage is unavailable. A zero-match result means only that the enabled detectors found nothing; it does not mean the text is safe to send. Detector scores are not calibrated probabilities, and overlapping candidates may have been suppressed.

Limits are the lower of gateway settings and 256 KiB per request body / 16,384 inspected characters. Serialized results are capped at 1 MiB. NER loading has a 60-second deadline and each inspection has 15 seconds. An inspection timeout terminates and reaps the worker, then starts a fresh one. While one job runs, another is rejected instead of queued.

The playground is a native Python local tool. Container exposure and remote access are outside this release. The regular gateway has no playground routes. Production readiness and provider reachability must be checked separately.
