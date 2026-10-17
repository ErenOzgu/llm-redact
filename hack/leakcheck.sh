#!/usr/bin/env bash
# Independent check of the redactor: an unrelated secret scanner must find secrets in a corpus of
# fake credentials, none after llm-redact has processed it, and restoring must give back every
# file byte for byte.
#
#   hack/leakcheck.sh [path to gitleaks]       needs Go, jq and gitleaks (or a path to it)
set -euo pipefail

cd "$(dirname "$0")/.."
GITLEAKS="${1:-gitleaks}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
die() { printf 'LEAKCHECK FAILED: %s\n' "$*" >&2; exit 1; }

go build -o "$work/llm-redact" ./cmd/llm-redact
go run ./hack/corpus "$work/raw" > /dev/null

scan() { # scan DIR REPORT -> number of findings
  "$GITLEAKS" detect --no-git --no-banner --source "$1" --report-format json --report-path "$2" --exit-code 0 > /dev/null 2>&1
  jq 'length' "$2"
}

before="$(scan "$work/raw" "$work/before.json")"
echo "gitleaks on the raw corpus:      $before findings ($(jq -r '[.[].RuleID] | unique | length' "$work/before.json") rules)"
[ "$before" -ge 20 ] || die "the corpus is too tame: gitleaks only found $before"

mkdir "$work/redacted" "$work/restored"
find "$work/raw" -maxdepth 1 -type f | while read -r f; do
  "$work/llm-redact" redact -q -map "$work/map.json" -o "$work/redacted/$(basename "$f")" "$f"
done
after="$(scan "$work/redacted" "$work/after.json")"
echo "gitleaks on the redacted corpus: $after findings"
if [ "$after" -ne 0 ]; then
  jq -r '.[] | "  \(.File):\(.StartLine) \(.RuleID)"' "$work/after.json"
  die "gitleaks still finds $after secrets after redaction"
fi

# Control: with only IP addresses masked the scanner must still see the secrets, otherwise a clean
# result above would prove nothing.
mkdir "$work/control"
find "$work/raw" -maxdepth 1 -type f | while read -r f; do
  "$work/llm-redact" redact -q -only IPV4 -o "$work/control/$(basename "$f")" "$f"
done
control="$(scan "$work/control" "$work/control.json")"
echo "control (only IPV4 masked):      $control findings"
[ "$control" -ge 20 ] || die "the control run found only $control: the scanner is not seeing leftovers"

find "$work/redacted" -maxdepth 1 -type f | while read -r f; do
  "$work/llm-redact" restore -strict -map "$work/map.json" "$f" > "$work/restored/$(basename "$f")"
done
diff -r "$work/raw" "$work/restored" > /dev/null || die "restoring did not give back the original files"
echo "restore: all $(find "$work/raw" -maxdepth 1 -type f | wc -l) files are identical to the originals"
echo "masked values: $(jq '.entries | length' "$work/map.json")"
echo "OK"
