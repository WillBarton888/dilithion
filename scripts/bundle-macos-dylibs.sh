#!/bin/bash
################################################################
#  bundle-macos-dylibs.sh
#  Make a macOS binary release self-contained by bundling all
#  non-system dynamic-library dependencies into <release_dir>/lib/.
#
#  Usage:
#    bundle-macos-dylibs.sh <release_dir> <binary> [<binary>...]
#
#  How it works:
#    Walks `otool -L` recursively starting from each given binary.
#    For every non-system dependency (i.e. NOT under /usr/lib or
#    /System and NOT already a relative @-prefixed path):
#      1. Copy the resolved file into <release_dir>/lib/ (preserve
#         basename only — strips Homebrew's versioned subpath).
#      2. Rewrite the dylib's own ID to @rpath/<basename>.
#      3. Rewrite the referrer's reference:
#         - Top-level binaries → @executable_path/lib/<basename>
#         - Sibling dylibs in lib/ → @loader_path/<basename>
#      4. Recurse into the freshly-copied dylib's own deps.
#
#    Top-level binaries also get an @rpath added pointing at lib/
#    so their own LC_LOAD_DYLIB entries can resolve through @rpath.
#
#  Why we need this:
#    macOS ships almost no third-party libraries (no leveldb,
#    no openssl3, no gmp, no miniupnpc). Without bundling, the
#    binary fails at startup with "dyld: Library not loaded:
#    /opt/homebrew/lib/libssl.3.dylib" on any machine that
#    doesn't have the exact same Homebrew layout.
################################################################

set -uo pipefail

RELEASE_DIR="$1"
shift
BINARIES=("$@")

LIB_DIR="${RELEASE_DIR}/lib"
mkdir -p "${LIB_DIR}"

# Track files we've already processed (avoid infinite loops).
PROCESSED_TMP=$(mktemp)
trap 'rm -f "${PROCESSED_TMP}"' EXIT

is_processed() {
    grep -qxF "$1" "${PROCESSED_TMP}" 2>/dev/null
}
mark_processed() {
    echo "$1" >> "${PROCESSED_TMP}"
}

# resolve_path: follow symlinks, fall back to the input.
resolve_path() {
    local p="$1"
    if command -v readlink >/dev/null 2>&1; then
        # macOS readlink doesn't have -f; use python or stat
        if command -v python3 >/dev/null 2>&1; then
            python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$p" 2>/dev/null
        else
            echo "$p"
        fi
    else
        echo "$p"
    fi
}

# Add @rpath/lib to top-level binaries so they can find dylibs in lib/.
for bin in "${BINARIES[@]}"; do
    if [ -f "$bin" ]; then
        install_name_tool -add_rpath "@executable_path/lib" "$bin" 2>/dev/null || true
    fi
done

# Worklist: each entry is "path:is_dylib" where is_dylib is 1 for files
# in lib/ (use @loader_path) and 0 for top-level binaries (use
# @executable_path/lib).
WORKLIST=()
for bin in "${BINARIES[@]}"; do
    WORKLIST+=("${bin}:0")
done

while [ ${#WORKLIST[@]} -gt 0 ]; do
    CURRENT_ENTRY="${WORKLIST[0]}"
    WORKLIST=("${WORKLIST[@]:1}")

    CURRENT_PATH="${CURRENT_ENTRY%:*}"
    IS_DYLIB="${CURRENT_ENTRY##*:}"

    if [ ! -f "${CURRENT_PATH}" ]; then
        continue
    fi
    if is_processed "${CURRENT_PATH}"; then
        continue
    fi
    mark_processed "${CURRENT_PATH}"

    # Read deps (skip the first line which is the file's own ID)
    DEPS=$(otool -L "${CURRENT_PATH}" 2>/dev/null | tail -n +2 | awk '{print $1}')

    for DEP in ${DEPS}; do
        # Skip system libraries
        case "${DEP}" in
            /usr/lib/*|/System/*)
                continue
                ;;
            @executable_path/*|@loader_path/*|@rpath/*)
                # Already bundled or @rpath — leave as-is
                continue
                ;;
        esac

        DEP_BASENAME=$(basename "${DEP}")

        # Skip self-reference (a dylib's own LC_ID_DYLIB shows up in some otool outputs)
        if [ "$(basename "${CURRENT_PATH}")" = "${DEP_BASENAME}" ]; then
            continue
        fi

        # Copy to lib/ if not already there
        if [ ! -f "${LIB_DIR}/${DEP_BASENAME}" ]; then
            REAL_DEP=$(resolve_path "${DEP}")
            if [ ! -f "${REAL_DEP}" ]; then
                echo "  ! WARNING: cannot find ${DEP} (resolved to ${REAL_DEP}), skipping"
                continue
            fi
            echo "  + ${DEP_BASENAME}"
            cp "${REAL_DEP}" "${LIB_DIR}/${DEP_BASENAME}"
            chmod u+w "${LIB_DIR}/${DEP_BASENAME}"
            # Set the dylib's own ID
            install_name_tool -id "@rpath/${DEP_BASENAME}" "${LIB_DIR}/${DEP_BASENAME}" 2>/dev/null || true
            # Add to worklist so its own deps get processed
            WORKLIST+=("${LIB_DIR}/${DEP_BASENAME}:1")
        fi

        # Rewrite the reference in the current binary/dylib
        if [ "${IS_DYLIB}" = "1" ]; then
            # Sibling reference within lib/
            install_name_tool -change "${DEP}" "@loader_path/${DEP_BASENAME}" "${CURRENT_PATH}" 2>/dev/null || true
        else
            # Binary reference into lib/
            install_name_tool -change "${DEP}" "@executable_path/lib/${DEP_BASENAME}" "${CURRENT_PATH}" 2>/dev/null || true
        fi
    done
done

echo ""
echo "  Bundled dylibs ($(ls "${LIB_DIR}" 2>/dev/null | wc -l | tr -d ' ')):"
ls -1 "${LIB_DIR}" 2>/dev/null | sed 's/^/    /'

# Verify: re-check binaries — none should reference Homebrew paths anymore
echo ""
echo "  Verification — remaining non-bundled deps in binaries:"
for bin in "${BINARIES[@]}"; do
    [ ! -f "$bin" ] && continue
    REMAINING=$(otool -L "$bin" 2>/dev/null | tail -n +2 | awk '{print $1}' | grep -vE '^(/usr/lib|/System|@executable_path|@loader_path|@rpath)' || true)
    if [ -n "${REMAINING}" ]; then
        echo "    $(basename "$bin") still references:"
        echo "${REMAINING}" | sed 's/^/      /'
    else
        echo "    $(basename "$bin"): all deps bundled or system ✓"
    fi
done
