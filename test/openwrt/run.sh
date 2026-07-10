#!/usr/bin/env bash
#
# OpenWrt deployment smoke for Subnetra — OPT-IN, slow, runs a real OpenWrt in
# qemu-system. It is the only test that exercises deploy/openwrt/subnetrad.init
# under genuine procd + BusyBox + opkg; the Ubuntu netns e2e (test/integration)
# and the qemu-user MIPS smoke (ci.yml) cannot. Driven by
# .github/workflows/openwrt.yml (workflow_dispatch + nightly), never on the PR
# hot path.
#
# We boot the OpenWrt **x86-64** generic image on purpose: procd/BusyBox and the
# init script are architecture-independent, so this fully validates the service
# logic, while booting fast under KVM (and tolerably under TCG). The MIPS angle —
# does the binary actually run on mipsel/mips — is already covered by the
# qemu-user execution smoke in the cross-build matrix, so we do not pay for slow
# qemu-system-mips here.
#
# Usage:
#   bash test/openwrt/run.sh
# Knobs (env): OPENWRT_VERSION, HTTP_PORT, BOOT_TIMEOUT, MEM_MB, QEMU_ACCEL,
#              OPENWRT_IMG (path to a pre-decompressed image, skips download).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

OPENWRT_VERSION="${OPENWRT_VERSION:-24.10.4}"
HTTP_PORT="${HTTP_PORT:-8000}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
MEM_MB="${MEM_MB:-512}"

IMG="openwrt-${OPENWRT_VERSION}-x86-64-generic-ext4-combined.img"
BASE_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/x86/64"

log() { printf '\033[1;34m[owrt]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[owrt:fail]\033[0m %s\n' "$*" >&2; exit 1; }

for tool in qemu-system-x86_64 qemu-img expect python3 curl gunzip sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

WORK="$(mktemp -d)"
HTTP_PID=""
cleanup() { [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

# --- 1. binary: build the x86-64 static musl daemon if not already present ----
if [ ! -x "$REPO/zig-out/bin/subnetrad" ] || ! file "$REPO/zig-out/bin/subnetrad" 2>/dev/null | grep -q 'x86-64'; then
	command -v zig >/dev/null 2>&1 || die "need zig to build the x86-64 binary (or pre-build zig-out/)"
	log "building x86_64-linux-musl ReleaseSmall"
	( cd "$REPO" && zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSmall )
fi
file "$REPO/zig-out/bin/subnetrad" | grep -q 'x86-64' || die "zig-out/bin/subnetrad is not an x86-64 binary"

# --- 2. OpenWrt image: (cached or) download, verify sha256, decompress, grow --
if [ -n "${OPENWRT_IMG:-}" ] && [ -f "${OPENWRT_IMG}" ]; then
	log "using pre-fetched image ${OPENWRT_IMG}"
	cp "${OPENWRT_IMG}" "$WORK/${IMG}"
else
	log "fetching OpenWrt ${OPENWRT_VERSION} x86-64 image"
	curl -fsSL "${BASE_URL}/${IMG}.gz"        -o "$WORK/${IMG}.gz"
	curl -fsSL "${BASE_URL}/sha256sums"       -o "$WORK/sha256sums"
	( cd "$WORK" && grep " \*${IMG}.gz\$" sha256sums | sed 's/\*//' | sha256sum -c - ) \
		|| die "OpenWrt image checksum mismatch"
	# gunzip exits 2 ("trailing garbage ignored") on OpenWrt's .gz; the decompressed
	# image is complete, so tolerate that one warning but still fail on real errors.
	gunzip -f "$WORK/${IMG}.gz" || { gz_rc=$?; [ "$gz_rc" -eq 2 ] || die "gunzip failed (rc=$gz_rc)"; }
fi
[ -f "$WORK/${IMG}" ] || die "OpenWrt image missing after fetch/decompress"
qemu-img resize -f raw "$WORK/${IMG}" +512M >/dev/null

# --- 3. stage artifacts the guest will fetch over qemu user-net --------------
SHARE="$WORK/share"; mkdir -p "$SHARE"
cp "$REPO/zig-out/bin/subnetrad"        "$SHARE/subnetrad"
cp "$REPO/zig-out/bin/subnetra"         "$SHARE/subnetra"
cp "$REPO/deploy/openwrt/subnetrad.init" "$SHARE/subnetrad.init"
cp "$REPO/deploy/spoke-a.json"          "$SHARE/spoke.json"
cp "$HERE/guest-smoke.sh"               "$SHARE/guest-smoke.sh"
# a config that PARSES but fails the --check sanity gate (missing/invalid PSK).
printf '{ "role": "spoke" }\n'          > "$SHARE/bad.json"

# kernel-matched tun module: the x86-64 generic image has no built-in tun, and
# the qemu guest cannot reach the opkg mirror (SLIRP egress is unreliable on CI
# runners). So fetch the kmod-tun .ipk HERE — where the runner has real network —
# and serve the extracted tun.ko for an offline insmod in the guest. The vermagic
# matches the booted image because both come from the same pinned release+target.
log "fetching kernel-matched kmod-tun for offline insmod"
kdir="$(curl -fsSL "${BASE_URL}/kmods/" | grep -oE 'href="[0-9][^"]*/"' | head -1 | sed 's/href="//; s|/"$||; s/"//')"
[ -n "$kdir" ] || die "could not locate the kmods dir under ${BASE_URL}/kmods/"
ipk="$(curl -fsSL "${BASE_URL}/kmods/${kdir}/" | grep -oE 'href="kmod-tun[^"]*\.ipk"' | head -1 | sed 's/href="//; s/"//')"
[ -n "$ipk" ] || die "could not locate kmod-tun .ipk under ${BASE_URL}/kmods/${kdir}/"
curl -fsSL "${BASE_URL}/kmods/${kdir}/${ipk}" -o "$WORK/kmod-tun.ipk"
# OpenWrt .ipk is a gzipped tar of {debian-binary, control.tar.gz, data.tar.gz}.
( cd "$WORK" && tar xzf kmod-tun.ipk ./data.tar.gz && mkdir -p kmod && tar xzf data.tar.gz -C kmod )
ko="$(find "$WORK/kmod" -name 'tun.ko*' | head -1)"
[ -n "$ko" ] || die "tun.ko not found inside ${ipk}"
case "$ko" in
	*.gz) gunzip -f "$ko" || { gz_rc=$?; [ "$gz_rc" -eq 2 ] || die "gunzip tun.ko rc=$gz_rc"; }; ko="${ko%.gz}" ;;
esac
cp "$ko" "$SHARE/tun.ko"
log "staged $(basename "$ko") (vermagic $(grep -ao 'vermagic=[0-9][^ ]*' "$SHARE/tun.ko" | head -1 | cut -d= -f2))"

# --- 4. serve the share dir; qemu user-net reaches it at 10.0.2.2 ------------
log "serving artifacts on :${HTTP_PORT}"
( cd "$SHARE" && exec python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 >/dev/null 2>&1 ) &
HTTP_PID=$!

# --- 5. pick acceleration: KVM if the runner exposes it, else TCG ------------
ACCEL="${QEMU_ACCEL:-}"
if [ -z "$ACCEL" ]; then
	if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL="kvm"; else ACCEL="tcg"; fi
fi
if [ "$ACCEL" = "kvm" ]; then CPU="host"; else CPU="max"; fi
log "qemu accel=${ACCEL} cpu=${CPU} mem=${MEM_MB}M boot_timeout=${BOOT_TIMEOUT}s"

# --- 6. boot + drive the guest over the serial console via expect ------------
cat > "$WORK/drive.expect" <<'EXPECT'
set img          $env(WORK_IMG)
set accel        $env(ACCEL)
set cpu          $env(CPU)
set mem          $env(MEM_MB)
set httpport     $env(HTTP_PORT)
set boot_timeout $env(BOOT_TIMEOUT)
set prompt {root@[A-Za-z0-9_.-]+:[^#]*#}

set timeout $boot_timeout
spawn qemu-system-x86_64 \
	-machine q35 -accel $accel -cpu $cpu -m $mem -smp 2 -no-reboot \
	-drive file=$img,format=raw,if=virtio \
	-netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
	-display none -serial stdio

expect {
	"Please press Enter to activate this console." {}
	"procd: - init complete -" {}
	timeout { puts "\n\[owrt\] boot timeout"; exit 2 }
}

# OpenWrt's serial console is askfirst: press Enter to spawn the passwordless
# root shell. procd's "- init complete -" is logged to the kernel ring buffer
# (not ttyS0) once logd takes over, so the askfirst banner is the only reliable
# console-ready signal. Kernel-log spam can also swallow a single Enter, so
# retry until the shell prompt actually appears.
sleep 2
set timeout 25
set got_prompt 0
for {set i 0} {$i < 8} {incr i} {
	send "\r"
	expect {
		-re $prompt { set got_prompt 1 }
		"Please press Enter to activate this console." {}
		timeout {}
	}
	if {$got_prompt} break
	sleep 2
}
if {!$got_prompt} { puts "\n\[owrt\] prompt timeout"; exit 2 }
set timeout 60

# bring up qemu user-net connectivity deterministically (no reliance on default
# OpenWrt LAN config): add the DHCP-pool address + default route + DNS forwarder.
send "NETDEV=br-lan; ip link show br-lan >/dev/null 2>&1 || NETDEV=\$(ip -o link | awk -F': ' '/ether/{print \$2; exit}'); ip address add 10.0.2.15/24 dev \$NETDEV; ip route add default via 10.0.2.2; printf 'nameserver 10.0.2.3\\n' > /etc/resolv.conf; echo NETUP_DONE\r"
expect {
	-re {[\r\n]NETUP_DONE[\r\n]} {}
	timeout { puts "\n\[owrt\] net-setup timeout"; exit 2 }
}
expect -re $prompt

# confirm the host HTTP server is reachable before handing off to the smoke
send "uclient-fetch -q -O /tmp/guest-smoke.sh http://10.0.2.2:$httpport/guest-smoke.sh && echo FETCH_OK || echo FETCH_FAIL\r"
expect {
	-re {[\r\n]FETCH_OK[\r\n]}   {}
	-re {[\r\n]FETCH_FAIL[\r\n]} { puts "\n\[owrt\] cannot reach host HTTP server"; exit 3 }
	timeout      { puts "\n\[owrt\] fetch timeout"; exit 3 }
}
expect -re $prompt

# run the real-userland smoke; scrape its result marker
set timeout 240
send "HTTP_PORT=$httpport sh /tmp/guest-smoke.sh\r"
set rc 99
expect {
	-re {SMOKE_RESULT=([0-9]+)} { set rc $expect_out(1,string) }
	timeout { puts "\n\[owrt\] smoke timeout"; exit 3 }
}

expect -re $prompt
set timeout 30
send "poweroff\r"
expect eof

exit [expr {$rc == 0 ? 0 : 1}]
EXPECT

WORK_IMG="$WORK/${IMG}" ACCEL="$ACCEL" CPU="$CPU" MEM_MB="$MEM_MB" \
	HTTP_PORT="$HTTP_PORT" BOOT_TIMEOUT="$BOOT_TIMEOUT" \
	expect -f "$WORK/drive.expect"
rc=$?

if [ "$rc" -eq 0 ]; then
	log "OpenWrt procd smoke PASSED"
else
	die "OpenWrt procd smoke FAILED (rc=$rc)"
fi
