#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
S="$ROOT/app/src/main/java/com/proxyvpn/app"
javac -encoding UTF-8 -d "$OUT" \
  "$ROOT/tests/offline/stubs/android/net/VpnService.java"   "$ROOT/tests/offline/stubs/android/os/ParcelFileDescriptor.java"   "$ROOT/tests/offline/stubs/android/util/Log.java" \
  "$ROOT/tests/offline/stubs/com/proxyvpn/app/ProxyConfig.java" \
  "$S/PacketCodec.java" "$S/ProxyTransport.java" "$S/DnsOverHttps.java" "$S/PacketEngine.java" \
  "$ROOT/tests/offline/src/com/proxyvpn/app/OfflineTests.java"
java -cp "$OUT" com.proxyvpn.app.OfflineTests
