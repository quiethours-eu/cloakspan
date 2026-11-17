#!/usr/bin/env bash
# Staging rehearsal: install PREV, upgrade to NEW, roll back, roll forward,
# then failure cases. Isolated Compose project; touches nothing else on the host.
# usage: rehearse.sh PREV_SHA NEW_SHA
set -uo pipefail

PREV="$1"
NEW="$2"
ROOT=/srv/cloakspan-rehearsal
REPO="$ROOT/repo"
LOGS="$ROOT/logs"
PROJECT=cloakspan-rehearsal
BASE=http://127.0.0.1:18480
MOCK=http://127.0.0.1:18491
FAILS=0
mkdir -p "$LOGS"

say() { printf '\n##### %s  [%s]\n' "$*" "$(date -u +%H:%M:%SZ)"; }
die() { echo "FATAL: $*"; exit 2; }

dc() {
  (cd "$REPO" && REHEARSAL_IMAGE="$PROJECT:$IMAGE_SHA" REHEARSAL_MOCK_IMAGE="$PROJECT:$PREV" \
    docker compose -p "$PROJECT" -f compose.yaml -f ../rehearsal.override.yaml "$@")
}

gateway_id() {
  docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=gateway"
}

build() {
  local sha="$1"
  git -C "$REPO" checkout -q --detach "$sha" || die "checkout $sha"
  # Same digest-pinned base image as `make release-image`.
  local base
  base="$(. "$REPO/deployment/docker/base-image.env" && echo "$BASE_IMAGE@$BASE_DIGEST")"
  echo "building $sha on $base"
  docker build -q -f "$REPO/deployment/docker/Dockerfile" --build-arg "BASE_REF=$base" \
    -t "$PROJECT:$sha" "$REPO" 2>&1 | tail -3
  docker image inspect "$PROJECT:$sha" >/dev/null 2>&1 || die "build $sha"
  docker image inspect -f 'image {{.Id}} size={{.Size}}' "$PROJECT:$sha"
}

wait_ready() {
  local start now
  start=$(date +%s.%N)
  for _ in $(seq 1 180); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/readyz")" = 200 ]; then
      now=$(date +%s.%N)
      printf 'ready after %.1fs\n' "$(echo "$now - $start" | bc)"
      return 0
    fi
    sleep 0.5
  done
  die "gateway not ready within 90s"
}

deploy() {
  # $1 = commit to run. The checkout supplies that version's compose.yaml.
  IMAGE_SHA="$1"
  git -C "$REPO" checkout -q --detach "$1" || die "checkout $1"
  dc up -d --no-build 2>&1 | grep -vE '^\s*$' | tail -6
  wait_ready
  docker inspect -f 'running image={{.Config.Image}} started={{.State.StartedAt}}' "$(gateway_id)"
}

save_logs() { docker logs "$(gateway_id)" >"$LOGS/gateway-$1.log" 2>&1; }

probe() {
  python3 "$ROOT/probe.py" --base "$BASE" --mock "$MOCK" --env-file "$REPO/.env" \
    --state "$ROOT/state.json" "$@" || FAILS=$((FAILS + 1))
}

expect() { # expect "name" command...
  local name="$1"; shift
  if "$@"; then echo "PASS  $name"; else echo "FAIL  $name"; FAILS=$((FAILS + 1)); fi
}

hardening() {
  local id line
  id="$(gateway_id)"
  line="$(docker inspect -f 'user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} capdrop={{.HostConfig.CapDrop}} secopt={{.HostConfig.SecurityOpt}} memory={{.HostConfig.Memory}} restart={{.HostConfig.RestartPolicy.Name}} health={{.State.Health.Status}}' "$id")"
  echo "$line"
  expect "runs as uid 10001" grep -q 'user=10001:10001' <<<"$line"
  expect "read-only root filesystem" grep -q 'readonly=true' <<<"$line"
  expect "all capabilities dropped" grep -q 'capdrop=\[ALL\]' <<<"$line"
  expect "no-new-privileges" grep -q 'no-new-privileges:true' <<<"$line"
  expect "1 GiB memory limit" grep -q 'memory=1073741824' <<<"$line"
  expect "write to root filesystem fails" bash -c "! docker exec $id sh -c 'echo x > /write-probe' 2>/dev/null"
  expect "published on loopback only" bash -c "docker port $id | grep -q '^8080/tcp -> 127.0.0.1:18480$'"
}

say "host"
. /etc/os-release
echo "os=$PRETTY_NAME kernel=$(uname -r) cpus=$(nproc) mem_mib=$(free -m | awk '/Mem:/{print $2}')"
echo "docker=$(docker version --format '{{.Server.Version}}') compose=$(docker compose version --short)"
echo "prev=$PREV new=$NEW"

say "1. install the previous commit"
[ -d "$REPO/.git" ] || git clone -q https://github.com/quiethours-eu/cloakspan "$REPO" || die "clone"
build "$PREV"
if [ ! -f "$REPO/.env" ]; then
  umask 077
  cat >"$REPO/.env" <<EOF
SAG_API_KEYS=sgw_live_$(openssl rand -hex 24):rehearsal-a:probe,sgw_live_$(openssl rand -hex 24):rehearsal-b:probe
SAG_VAULT_KEY=$(openssl rand -hex 32)
SAG_TOKEN_KEY=$(openssl rand -hex 32)
SAG_EXTERNAL_BASE_URL=http://mockprovider:9000/v1
SAG_LOCAL_BASE_URL=http://mockprovider:9000/v1
SAG_EGRESS_ALLOW_PRIVATE=true
SAG_BIND_HOST=127.0.0.1
SAG_PORT=18480
MOCK_PORT=18491
SAG_REQUEST_TIMEOUT_SECONDS=20
SAG_RATE_LIMIT_PER_MINUTE=120
SAG_METRICS_TOKEN=$(openssl rand -hex 24)
EOF
fi
deploy "$PREV"
sleep 16 # one health-check interval, so the health status is meaningful
hardening
probe --phase install --checks basic,prev

say "2. upgrade to the release commit"
save_logs 1-install
build "$NEW"
deploy "$NEW"
sleep 16
hardening
probe --phase upgrade --old-from install --checks basic,old_token,new

say "3. roll back to the previous commit"
save_logs 2-upgrade
deploy "$PREV"
probe --phase rollback --old-from upgrade --checks basic,old_token,prev

say "4. roll forward to the release commit"
save_logs 3-rollback
deploy "$NEW"
probe --phase rollforward --checks basic,new

say "5a. failure: the gateway process is killed"
id="$(gateway_id)"
before="$(docker inspect -f '{{.State.StartedAt}}' "$id")"
pid="$(docker inspect -f '{{.State.Pid}}' "$id")"
grep -q "$id" "/proc/$pid/cgroup" || die "pid $pid is not in the gateway container"
kill -9 "$pid"
sleep 2
wait_ready
after="$(docker inspect -f '{{.State.StartedAt}} restarts={{.RestartCount}}' "$(gateway_id)")"
echo "started before=$before after=$after"
expect "container restarted by its restart policy" bash -c "[ '$before' != '${after%% *}' ]"
probe --phase crash --checks basic

say "5b. failure: the provider is down"
dc stop mockprovider 2>&1 | tail -1
probe --phase provider-down --checks provider_down
dc start mockprovider 2>&1 | tail -1
sleep 2
probe --phase provider-back --checks basic

say "5c. failure: required secrets are missing"
expect "compose refuses to start without required values" bash -c \
  "cd $REPO && ! docker compose -p $PROJECT-missing --env-file /dev/null -f compose.yaml config >/dev/null 2>$LOGS/missing-compose.txt"
tail -1 "$LOGS/missing-compose.txt" | cut -c1-200
grep -vE '^SAG_VAULT_KEY=' "$REPO/.env" >"$ROOT/no-vault-key.env"
timeout 60 docker run --rm --network none --read-only --cap-drop ALL \
  --env-file "$ROOT/no-vault-key.env" -e SAG_ENVIRONMENT=production \
  "$PROJECT:$NEW" >"$LOGS/missing-vault-key.txt" 2>&1
code=$?
echo "exit=$code"
grep -E 'SAG_VAULT_KEY' "$LOGS/missing-vault-key.txt" | tail -1 | cut -c1-220
expect "production start without SAG_VAULT_KEY exits non-zero" bash -c "[ $code -ne 0 ] && [ $code -ne 124 ]"

say "5d. failure: a weak metrics token"
grep -vE '^SAG_METRICS_TOKEN=' "$REPO/.env" >"$ROOT/weak-metrics.env"
timeout 60 docker run --rm --network none --read-only --cap-drop ALL \
  --env-file "$ROOT/weak-metrics.env" -e SAG_ENVIRONMENT=production -e SAG_METRICS_TOKEN=short \
  "$PROJECT:$NEW" >"$LOGS/weak-metrics-token.txt" 2>&1
code=$?
echo "exit=$code"
grep -E 'SAG_METRICS_TOKEN' "$LOGS/weak-metrics-token.txt" | tail -1 | cut -c1-220
expect "start with a short SAG_METRICS_TOKEN exits non-zero" bash -c "[ $code -ne 0 ] && [ $code -ne 124 ]"
rm -f "$ROOT/no-vault-key.env" "$ROOT/weak-metrics.env"

say "6. audit stream and log hygiene"
save_logs 4-final
cat "$LOGS"/gateway-*.log >"$LOGS/all-gateway.log"
for reason in invalid_api_key request_too_large invalid_json rate_limit_exceeded \
  provider_unavailable provider_timeout provider_error egress_blocked destination_unavailable; do
  printf 'audit events with error=%s: %s\n' "$reason" \
    "$(grep -c "\"error\": \"$reason\"" "$LOGS/gateway-4-final.log")"
done
leaks=0
while IFS= read -r needle; do
  [ -n "$needle" ] || continue
  n="$(grep -cF -- "$needle" "$LOGS/all-gateway.log")"
  leaks=$((leaks + n))
done <<EOF
jana.berzina@example.test
LV80BANK0000435195001
AKIAIOSFODNN7EXAMPLE
$(grep -E '^SAG_(VAULT_KEY|TOKEN_KEY|METRICS_TOKEN)=' "$REPO/.env" | cut -d= -f2)
$(grep -E '^SAG_API_KEYS=' "$REPO/.env" | cut -d= -f2 | tr ',' '\n' | cut -d: -f1)
EOF
echo "log lines containing a synthetic value or a secret: $leaks (of $(wc -l <"$LOGS/all-gateway.log") lines)"
expect "no synthetic value or secret in any gateway log" bash -c "[ $leaks -eq 0 ]"

say "result"
echo "failed checks or probes: $FAILS"
exit $((FAILS > 0))
