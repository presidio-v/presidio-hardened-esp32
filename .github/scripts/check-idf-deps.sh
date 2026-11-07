#!/usr/bin/env bash
#
# Dependency pin check for idf_component.yml.
#
# Why this and not an OSV scan: the ESP Component Registry is not an OSV
# ecosystem, and today the manifest declares no managed components at all,
# only the ESP-IDF framework requirement ("idf"). There is nothing an
# OSV-based scanner could resolve. This check keeps it that way on purpose:
# any component dependency added later must be pinned to an exact version
# (registry) or a full commit SHA (git), so a reviewer can audit exactly
# what is pulled in and Dependabot-style bumps stay explicit.
#
# What it does NOT cover:
#   - ESP-IDF itself (including its bundled mbedTLS). The "idf" entry is a
#     framework range by design; which IDF versions are built is set by the
#     build matrix in .github/workflows/build.yml, and IDF advisories have to
#     be tracked upstream (github.com/espressif/esp-idf/security).
#   - Vulnerabilities in pinned components. A pin is not a vulnerability
#     scan; if managed components are ever added, add an advisory check too.
#   - dependencies.lock in consuming projects, which this repo does not own.
#
# Usage: check-idf-deps.sh [path/to/idf_component.yml]
# Requires mikefarah yq v4 (preinstalled on GitHub-hosted Ubuntu runners).

set -euo pipefail

manifest="${1:-idf_component.yml}"

if ! command -v yq >/dev/null 2>&1; then
    echo "error: yq (mikefarah v4) is required" >&2
    exit 2
fi
if [ ! -f "$manifest" ]; then
    echo "error: $manifest not found" >&2
    exit 2
fi

# Fail closed if the manifest does not parse.
yq -e '.' "$manifest" >/dev/null

semver_re='^(==)?[0-9]+\.[0-9]+\.[0-9]+(~[0-9]+)?$'
sha_re='^[0-9a-f]{40}$'
failures=0
checked=0

names="$(yq -r '(.dependencies // {}) | keys | .[]' "$manifest")"

while IFS= read -r name; do
    [ -n "$name" ] || continue
    if [ "$name" = "idf" ]; then
        echo "skip  idf: framework requirement ($(DEP="$name" yq -r '.dependencies[strenv(DEP)] | (.version // .)' "$manifest")), covered by the build matrix"
        continue
    fi
    checked=$((checked + 1))

    kind="$(DEP="$name" yq -r '.dependencies[strenv(DEP)] | tag' "$manifest")"
    version=""
    git_url=""
    local_path=""
    case "$kind" in
    '!!str' | '!!int' | '!!float')
        version="$(DEP="$name" yq -r '.dependencies[strenv(DEP)]' "$manifest")"
        ;;
    '!!map')
        version="$(DEP="$name" yq -r '.dependencies[strenv(DEP)].version // ""' "$manifest")"
        git_url="$(DEP="$name" yq -r '.dependencies[strenv(DEP)].git // ""' "$manifest")"
        local_path="$(DEP="$name" yq -r '(.dependencies[strenv(DEP)].path // .dependencies[strenv(DEP)].override_path) // ""' "$manifest")"
        ;;
    *)
        echo "FAIL  $name: unsupported dependency form ($kind)"
        failures=$((failures + 1))
        continue
        ;;
    esac

    if [ -n "$local_path" ]; then
        echo "FAIL  $name: local path dependency ($local_path) cannot be pinned or audited"
        failures=$((failures + 1))
    elif [ -n "$git_url" ]; then
        if [[ "$version" =~ $sha_re ]]; then
            echo "ok    $name: git $git_url @ $version"
        else
            echo "FAIL  $name: git dependency must pin a full 40-char commit SHA (got '${version:-<none>}')"
            failures=$((failures + 1))
        fi
    elif [[ "$version" =~ $semver_re ]]; then
        echo "ok    $name: $version"
    else
        echo "FAIL  $name: registry dependency must pin an exact version like 1.2.3 (got '${version:-<none>}')"
        failures=$((failures + 1))
    fi
done <<<"$names"

if [ "$checked" -eq 0 ]; then
    echo "No managed component dependencies in $manifest; nothing to scan."
fi
if [ "$failures" -gt 0 ]; then
    echo "$failures unpinned or unsupported dependency entr$([ "$failures" -eq 1 ] && echo y || echo ies) in $manifest" >&2
    exit 1
fi
