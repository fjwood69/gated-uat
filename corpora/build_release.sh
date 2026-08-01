#!/usr/bin/env bash
# THE PUBLISHED RECIPE for the demo corpus release artifact.
#
# The outer digest of what this produces gets committed into `gated` as a literal and becomes the
# trust root. Every future pin update is a human comparing digests, so the property that matters is
# narrow and worth stating exactly:
#
#     NO REBUILD THIS PROJECT PERFORMS EVER CHANGES THE DIGEST WITHOUT A CONTENT CHANGE.
#
# That is NOT "reproducible on any machine by anyone" — an earlier version of this file claimed that,
# and the claim was false in at least three ways at once. If the digest churns without content
# changing, the reviewer learns churn is normal and rubber-stamps it, which destroys the one human
# review step protecting the pin.
#
# ⚠ WHAT AN EARLIER VERSION GOT WRONG, kept here because the corrections are the content:
#   * NO MODE CLAMP. tar stores permission bits; git records only the executable bit, so a checkout's
#     modes come from the builder's umask. This host's umask 0002 gives 664; a umask 022 host gives
#     644 — different digest, identical content. Now clamped.
#   * NO LOCALE PIN. `sort` collates by LC_COLLATE, so member order could vary by builder locale.
#     Today's names probably collate identically under C and en_CA — i.e. the digest was stable BY
#     LUCK, and a future member named `-mutated-10` is where luck ends. Now pinned to C.
#   * THE MEMBER LIST FAILED OPEN. It was built by a `while read` fed from process substitution,
#     whose exit status is invisible to `set -e`. If `find` died or the directory vanished, the loop
#     read zero lines, the archive shipped WITHOUT ANY FIXTURES, both builds agreed, and the script
#     printed success. An empty result treated as a value, in shell form.
#   * HARDLINKS were not considered at all. GNU tar stores the second of two hardlinked members as a
#     link entry, so link structure — a property of the CHECKOUT, not the tree — would change the
#     archive. It would also be refused by the consumer's member-type allowlist.
#   * IT CLAIMED TOO MUCH. Two builds, one machine, one second, identical mtimes: correlated on every
#     environmental axis. Removing any single clamp would still have passed it.
set -euo pipefail

# Pin collation and message language for every tool below. Cheap, and removes a whole axis.
export LC_ALL=C

CORPORA="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-$(mktemp -d)}"          # never a predictable /tmp path: `>` and `mv` follow symlinks
ARTIFACT="${OUT_DIR}/gated-demo-corpus.tar"
EPOCH=0                                # FIXED, never "now"

cd "$CORPORA"

# ---- provenance: refuse to seal an unreviewable tree ------------------------------------------
COMMIT="$(git rev-parse HEAD)"
if [ -n "$(git status --porcelain -- "$CORPORA")" ]; then
  echo "### RECIPE REFUSED — the corpus tree is DIRTY. A digest that cannot be tied to a commit is"
  echo "### not reviewable: 'digest changed' must mean 'content changed', and an uncommitted edit"
  echo "### breaks that link silently. Commit first. ###"
  exit 1
fi

# ---- members come from the corpus's OWN manifest, not from patterns restated here --------------
# SHA256SUMS is generated from expectations.py, which is the single source of truth for membership
# and is enforced by pretag_gate.py. An earlier version restated the member set as `find -name`
# patterns — a SECOND source of truth that would rot first, and one that would also have swept in the
# v1 fixtures that are deliberately present-but-not-shipped.
mapfile -t members < <(awk '{print $NF}' SHA256SUMS)
[ "${#members[@]}" -gt 0 ] || { echo "### RECIPE REFUSED — SHA256SUMS yielded no members ###"; exit 1; }
members+=(SHA256SUMS)                  # the manifest ships with what it describes

# ---- preflight: every member must be a plain, unlinked, present file ---------------------------
for m in "${members[@]}"; do
  [ -e "$m" ]   || { echo "### RECIPE REFUSED — member missing: $m ###"; exit 1; }
  [ ! -L "$m" ] || { echo "### RECIPE REFUSED — member is a SYMLINK: $m (tar would archive the link"
                     echo "### text, and the consumer's type allowlist would refuse it) ###"; exit 1; }
  [ -f "$m" ]   || { echo "### RECIPE REFUSED — member is not a regular file: $m ###"; exit 1; }
  links="$(stat -c '%h' "$m")"
  [ "$links" = "1" ] || { echo "### RECIPE REFUSED — member is HARDLINKED (${links} links): $m."
                          echo "### tar would store it as a link entry, making the archive depend on"
                          echo "### the checkout's link structure rather than on content. ###"; exit 1; }
done

# ---- internal consistency: the manifest must already describe the tree -------------------------
# Without this the recipe will happily seal a self-contradicting artifact whose outer digest verifies
# and whose every per-member check then fails at the consumer.
sha256sum --check --strict --quiet SHA256SUMS || {
  echo "### RECIPE REFUSED — the corpus does not match its own SHA256SUMS. Regenerate the manifest"
  echo "### before sealing; do not seal an artifact that contradicts itself. ###"; exit 1; }

# ---- build --------------------------------------------------------------------------------------
build() {
  # --mode      clamp permissions (VERIFIED on GNU tar 1.35: 664 on disk -> -rw-r--r-- archived)
  # --sort=name deterministic member order, with LC_ALL=C pinning the collation
  # --mtime     clamp timestamps; when a file was touched is not its content
  # --owner/--group/--numeric-owner   who built it is not its content
  # --format=gnu  fewer variable fields than pax, which can carry atime/ctime and implementation-
  #               specific keywords; the digest is only ever PRODUCED here, and readers only extract
  # UNCOMPRESSED, deliberately: gzip's DEFLATE stream is not guaranteed identical across
  # implementations or versions, so compressing would make the trust root gzip-version-dependent to
  # save a few kilobytes on nine small text files.
  tar --mode='u+rwX,go+rX,go-w' --sort=name --mtime="@${EPOCH}" \
      --owner=0 --group=0 --numeric-owner --format=gnu \
      -C "$CORPORA" -cf "$1" "${members[@]}"
}

build "${ARTIFACT}.a"
build "${ARTIFACT}.b"
A="$(sha256sum "${ARTIFACT}.a" | cut -d' ' -f1)"
B="$(sha256sum "${ARTIFACT}.b" | cut -d' ' -f1)"
if [ "$A" != "$B" ]; then
  echo "### RECIPE REFUSED — two builds of the same tree disagreed. ###"
  exit 1
fi
mv "${ARTIFACT}.a" "$ARTIFACT"
rm -f "${ARTIFACT}.b"

# ---- the toolchain manifest: what the claim is CONDITIONAL on -----------------------------------
cat > "${OUT_DIR}/BUILD-ENVIRONMENT.txt" <<EOF
artifact_sha256   $A
source_commit     $COMMIT
members           ${#members[@]}
tar               $(tar --version | head -1)
sha256sum         $(sha256sum --version | head -1)
LC_ALL            ${LC_ALL}
umask             $(umask)
built_on          $(uname -sr)
EOF

echo "members       : ${#members[@]}"
echo "source commit : $COMMIT"
echo "artifact      : $ARTIFACT"
echo "outer digest  : $A"
echo
echo "### SAME-ENVIRONMENT SELF-CHECK PASSED — necessary, NOT sufficient. ###"
echo "### Two builds one second apart on one machine are correlated on every environmental axis:"
echo "### umask, locale, uid/gid, timezone, toolchain and all source mtimes are identical between"
echo "### them, so removing any single clamp above would STILL pass this check. What it genuinely"
echo "### catches is per-invocation randomness and a tree mutated mid-build. The real proof is a"
echo "### clean-environment rebuild under a different umask and locale; BUILD-ENVIRONMENT.txt"
echo "### records what this digest is conditional on so that proof can be attempted. ###"
