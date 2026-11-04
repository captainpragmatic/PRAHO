#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in test|build) mode=$1 ;; *) echo 'Usage: build.sh test|build' >&2; exit 2 ;; esac
recipe_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$recipe_dir/../../.." && pwd)
source_sha=f9506a855c05babdf6882b43b6d67975c8fdc8eb362a85aa5e2ab6003517e912
source_url=https://codeload.github.com/crowdsecurity/cs-firewall-bouncer/tar.gz/4c315193cd4f19e3937cdee2f15183ec4d602f56
build_context=$(mktemp -d "${TMPDIR:-/tmp}/praho-crowdsec-patch.XXXXXXXX")
trap 'rm -rf -- "$build_context"' EXIT

if [[ -n ${CROWDSEC_PATCH_SOURCE:-} ]]; then
    cp -- "$CROWDSEC_PATCH_SOURCE" "$build_context/source.tar.gz"
else
    curl --location --fail --silent --show-error --max-time 120 "$source_url" -o "$build_context/source.tar.gz"
fi
actual_sha=$(shasum -a 256 "$build_context/source.tar.gz")
if [[ ${actual_sha%% *} != "$source_sha" ]]; then
    echo 'Pinned source archive SHA-256 mismatch' >&2
    exit 1
fi
cp -- "$recipe_dir/Dockerfile" "$build_context/Dockerfile"
cp -- "$recipe_dir/set_only_intervals_test.go" "$build_context/set_only_intervals_test.go"
cp -- "$repo_dir/LICENSE.md" "$build_context/PRAHO-LICENSE.md"
cp -- "$recipe_dir/build.sh" "$build_context/build.sh"
cp -- "$recipe_dir/README.md" "$build_context/README.md"
if [[ ${CROWDSEC_PATCH_BASELINE:-0} == 1 ]]; then
    : > "$build_context/patch.diff"
    apply_patch=0
else
    cp -- "$recipe_dir/../patches/0001-set-only-intervals.patch" "$build_context/patch.diff"
    apply_patch=1
fi

build_args=(--progress=plain --build-arg "APPLY_PATCH=$apply_patch")
if [[ ${CROWDSEC_PATCH_NO_CACHE:-0} == 1 ]]; then
    build_args+=(--no-cache)
fi
if [[ $mode == test ]]; then
    docker build "${build_args[@]}" --target tested "$build_context"
else
    output_dir=${CROWDSEC_PATCHED_OUTPUT:-$repo_dir/build/crowdsec-patched}
    mkdir -p -- "$output_dir"
    docker build "${build_args[@]}" --output "type=local,dest=$output_dir" "$build_context"
    shasum -a 256 "$output_dir/crowdsec-firewall-bouncer-amd64" "$output_dir/crowdsec-firewall-bouncer-arm64"
fi
