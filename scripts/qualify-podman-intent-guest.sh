#!/bin/sh
# Source-only draft. Run only in separately attested disposable no-NIC VM.
set -eu
umask 077
if [ "$#" -ne 3 ]; then echo 'usage: runner REVIEWED_TEST_BINARY SYNTHETIC_ARCHIVE PRIVATE_PARENT' >&2; exit 2; fi
binary=$1 archive=$2 parent=$3
# Independently reproduced: base 7d54ca5, test blob 4cbd336978e77a6cb38a44b44ffb26812c97dbd3,
# Go 1.25.7, CGO_ENABLED=0, -trimpath -buildvcs=false.
binary_sha=36eccede1ae0b4792a7b673fdf278e02650e76f71fc81deb15a9b202e4c1abcc
case "$binary:$archive:$parent" in /*:/*:/*) ;; *) exit 2;; esac
case "$binary_sha" in *[!0-9a-f]*|'') exit 2;; esac
[ "${#binary_sha}" -eq 64 ] || exit 2
[ "$(id -u)" = 1000 ] && [ "$(id -g)" = 1000 ] && [ "$(id -G)" = 1000 ] && [ -f "$binary" ] && [ ! -L "$binary" ] && [ -f "$archive" ] && [ ! -L "$archive" ] && [ -d "$parent" ] && [ ! -L "$parent" ] || exit 2
[ "$(stat -c '%u:%a' "$parent")" = "$(id -u):700" ] || exit 2
[ ! -e /etc/containers/mounts.conf ] && [ ! -L /etc/containers/mounts.conf ] && [ ! -e /usr/share/containers/mounts.conf ] && [ ! -L /usr/share/containers/mounts.conf ] || exit 2
base=$(mktemp -d "$parent/metaclaw-guest-qualification.XXXXXXXX")
chmod 700 "$base"
mkdir -m 700 "$base/root" "$base/runroot" "$base/tmp" "$base/home" "$base/runtime" "$base/config" "$base/hooks" "$base/bin" "$base/journal"
cp --reflink=never -- "$binary" "$base/testbin"
cp --reflink=never -- "$archive" "$base/image.tar"
chmod 500 "$base/testbin"; chmod 400 "$base/image.tar"
[ "$(sha256sum "$base/testbin" | cut -d' ' -f1)" = "$binary_sha" ] || exit 2
[ "$(sha256sum "$base/image.tar" | cut -d' ' -f1)" = 614408851026f406fa3848729c893ba29a7e963dbe2ed6bf9534a53e689029c0 ] || exit 2
printf '[containers]\nvolumes = []\n[engine]\nhooks_dir = []\n' > "$base/config/containers.conf"
printf '[storage]\ndriver = "vfs"\n' > "$base/config/storage.conf"
image=sha256:9779a4143ae4607c8702ee40a94ae02c0c7b759c567588b4ef95a07d3208e005
# All subsequent commands use an empty environment and private state. Guest
# interface checks do not attest host VM configuration or host isolation.
run() { /usr/bin/env -i PATH="$base/bin:/usr/bin:/bin" HOME="$base/home" XDG_RUNTIME_DIR="$base/runtime" XDG_CONFIG_HOME="$base/config" TMPDIR="$base/tmp" CONTAINERS_CONF="$base/config/containers.conf" CONTAINERS_STORAGE_CONF="$base/config/storage.conf" QUAL_BASE="$base" QUAL_IMAGE="$image" QUAL_UID="$(id -u)" "$@"; }
p() { run /usr/bin/podman --root "$base/root" --runroot "$base/runroot" --tmpdir "$base/tmp" --storage-driver vfs --events-backend none --hooks-dir "$base/hooks" "$@"; }
echo "qualification evidence retained: $base"
# Preflight is in the compiled test binary, not a caller-provided attestation.
run_one() {
  name=$1 timeout=$2 output="$base/$1.test-output"
  run "$base/testbin" -test.v -test.run "^${name}$" -test.count=1 -test.timeout="$timeout" > "$output" 2>&1 || return 1
  [ "$(grep -c '^=== RUN   ' "$output")" -eq 1 ] && [ "$(grep -Fxc "=== RUN   $name" "$output")" -eq 1 ] && [ "$(grep -c "^--- PASS: $name " "$output")" -eq 1 ] && [ "$(grep -Fxc PASS "$output")" -eq 1 ]
}
run_one TestGuestEnvironmentPreflight 15s
[ "$(p info --format '{{.Host.Security.Rootless}}')" = true ] || exit 2
[ "$(p info --format '{{.Store.GraphRoot}}')" = "$base/root" ] || exit 2
[ "$(p info --format '{{.Store.RunRoot}}')" = "$base/runroot" ] || exit 2
p load -i "$base/image.tar" > "$base/load.out"
actual_id=$(p image inspect --format '{{.Id}}' "$image")
actual_id=${actual_id#sha256:}
[ "${#actual_id}" -eq 64 ] || exit 2
case "$actual_id" in *[!0-9a-f]*|'') exit 2;; esac
[ "$actual_id" = "${image#sha256:}" ] || exit 2
cat > "$base/bin/podman" <<'WRAPPER'
#!/bin/sh
set -eu
[ "$#" -eq 7 ] && [ "$1" = create ] && [ "$2" = --name ] && [ "$4" = --label ] && [ "$6" = --network=none ] && [ "$7" = "$QUAL_IMAGE" ] || exit 90
marker=${3#metaclaw-intent-}
[ "$3" = "metaclaw-intent-$marker" ] && [ "${#marker}" -eq 32 ] || exit 90
case "$marker" in *[!0-9a-f]*|'') exit 90;; esac
[ "$5" = "io.metaclaw.intent=$marker" ] || exit 90
exec /usr/bin/podman --root "$QUAL_BASE/root" --runroot "$QUAL_BASE/runroot" --tmpdir "$QUAL_BASE/tmp" --storage-driver vfs --events-backend none --hooks-dir "$QUAL_BASE/hooks" create --pull=never --image-volume=ignore "$2" "$3" "$4" "$5" "$6" "$7"
WRAPPER
chmod 700 "$base/bin/podman"
run_one TestGuestIntentRefusesOwner 90s
