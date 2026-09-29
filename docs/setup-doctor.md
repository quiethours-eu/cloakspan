# Setup doctor

`cloakspan doctor` inspects the environment visible to that process and the local
policy, filter, and model files it references. It works when production settings
prevent the gateway from starting. It does not edit configuration, generate
credentials, download a model, run inference, or contact providers by default.

```sh
cloakspan doctor
cloakspan doctor --format json
cloakspan doctor --format json --strict
```

`secure-ai-gateway doctor` is the same command. With no arguments, either name
still starts the server. Doctor reads inherited environment variables; it does
not load `.env`. A host shell and a Docker Compose service may have different
values. Check the service environment when diagnosing the deployed gateway.

Optional checks require explicit flags:

```sh
cloakspan doctor --load-model
cloakspan doctor --probe-providers --timeout 5
```

`--load-model` verifies the configured model, loads its local backend, and runs
one synthetic smoke input in a subprocess with a 60-second deadline. The report
separates declared manifest languages, mapped backend labels, and labels seen in
that smoke input. It is not an accuracy benchmark.

`--probe-providers` enables DNS and an authenticated `GET /models` request for
effective configured destinations. Configured provider credentials are sent to
their destinations, through an ambient proxy only if `SAG_TRUST_ENV_PROXY` is
enabled for that destination. There are no chat completion requests. Redirects are not
followed, responses are capped at 64 KiB, each provider has a five-second
default deadline, and the whole probe phase has a 15-second budget. Use
`--timeout` to change the per-provider deadline up to 15 seconds. A successful
listing confirms that endpoint only. A `404` or `405` means model listing is
unsupported, not that inference is broken.

In a running Compose service:

```sh
docker compose exec gateway cloakspan doctor
```

For a stopped service, override the image's uvicorn entry point:

```sh
docker compose run --rm --no-deps --entrypoint cloakspan gateway doctor
```

Compose interpolation may reject missing required variables before doctor runs.
Resolve those Compose errors first, or run the installed command with the
intended environment directly. Doctor does not inspect host port publication or
reverse proxies. A process listening on `0.0.0.0` is not by itself proof of
public exposure.

## Reading the report

Checks have stable IDs and one of `pass`, `warn`, `fail`, or `skip`. A skip names
the prerequisite or opt-in flag. The JSON format has `schema_version: 1`,
summary counts, a configured detector inventory, and an effective routing mode.
The report includes sanitized destination scheme, host, and port only. It never
prints API keys, root secrets, policy source, custom terms, regexes, provider
response bodies, or raw parser errors. Custom policy versions and filter
fingerprints are withheld when they could reveal operator content.

A shortened redacted JSON example:

```json
{
  "schema_version": 1,
  "gateway_version": "0.1.0a1",
  "environment": "production",
  "routing_mode": "all",
  "status": "warning",
  "counts": {"pass": 0, "warn": 1, "fail": 0, "skip": 0},
  "coverage": [],
  "checks": [
    {
      "id": "detection.ner",
      "status": "warn",
      "summary": "Contextual NER is disabled",
      "remediation": "Configure SAG_NER_MODEL_PATH to inspect contextual entities.",
      "details": {"enabled": false}
    }
  ]
}
```

The example omits other checks and inventory entries for brevity.

Exit code `0` means no failed checks; warnings remain visible. `--strict` makes
warnings return `1` too. Failed checks return `1`. Invalid command use or an
unexpected diagnostics failure returns `2`.

Example CI step:

```sh
cloakspan doctor --format json --strict > doctor-report.json
```

The default run cannot confirm hostname resolution, provider reachability,
model loading, detection accuracy, or production readiness. Contextual NER
disabled is a warning. In `SAG_LOCAL_ROUTING=detected`, the configured detector
set determines what counts as detected; test it against representative data.
The gateway's vault mappings are process local, so a restart loses them even
when persistent root keys are configured.
