#!/usr/bin/env bash
# Download the public real-world s390x binaries used by test/real-binaries.sh. Nothing is
# committed; the files land in <dest> (default: ./real-samples), checked against pinned SHA-256.
#
#   test/fetch-real-samples.sh [dest]
#
# Debian 13 "trixie" (s390x, gcc -march=z196 baseline) and Ubuntu 25.04 "plucky" (s390x, z15
# baseline, more vector code). Fetched from the archive pools, falling back to
# snapshot.debian.org for the Debian packages once they leave the pool.
#   glibc 2.41-12+deb13u4      libc6           LGPL-2.1+  libc.so.6           (Debian)
#   coreutils 9.7-3            coreutils       GPL-3+     ls, sort            (Debian)
#   zlib 1.3.1-1+b1            zlib1g          Zlib       libz.so.1.3.1       (Debian)
#   busybox 1.37.0-6+b9        busybox-static  GPL-2      busybox (static)    (Debian)
#   glibc 2.41-6ubuntu1        libc6           LGPL-2.1+  libc.so.6 -> libc-ubuntu.so.6
set -euo pipefail
DEST=${1:-real-samples}
mkdir -p "$DEST"
cd "$DEST"
DEB=https://deb.debian.org/debian
SNAP=https://snapshot.debian.org/archive/debian/20261025T000000Z
UB=http://ports.ubuntu.com/ubuntu-ports
debs=(
"$DEB pool/main/g/glibc/libc6_2.41-12+deb13u4_s390x.deb c6e658d8e17d885c831ad1275501ef1abdadc6c93e9ac7758cfd1e5cde2d608b"
"$DEB pool/main/c/coreutils/coreutils_9.7-3_s390x.deb 3226ac66d2bebad8e06b8a58732cf997dd5da532ab4cd844ea74b6d59b052de9"
"$DEB pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+b1_s390x.deb e38a94c60e944dfcf1937a12b02785afbbb2bedf356da18984c4dac0acc47ed9"
"$DEB pool/main/b/busybox/busybox-static_1.37.0-6+b9_s390x.deb 6e6d4257dd06c7a07aa88f207cc0e8b6d1a2e06f7f118d528af31b2169b51978"
"$UB pool/main/g/glibc/libc6_2.41-6ubuntu1_s390x.deb 24634d6c6818e8498208a4379a3870883fc9f4d006729987bf4bfbae6fd60415"
)
for e in "${debs[@]}"; do
	set -- $e
	f=$(basename "$2")
	if [[ ! -s $f ]]; then
		curl -fsSL --retry 3 -o "$f.part" "$1/$2" || curl -fsSL --retry 3 -o "$f.part" "$SNAP/$2"
		mv "$f.part" "$f"
	fi
	echo "$3  $f" | sha256sum -c -
done
extract() { # deb member out
	local t
	t=$(mktemp -d .x.XXXXXX)
	(cd "$t" && ar x "../$1" && tar xf data.tar.* "./$2")
	cp "$t/$2" "$3"
	rm -rf "$t"
}
[[ -s libc.so.6 ]] || extract libc6_2.41-12+deb13u4_s390x.deb usr/lib/s390x-linux-gnu/libc.so.6 libc.so.6
[[ -s libc-ubuntu.so.6 ]] || extract libc6_2.41-6ubuntu1_s390x.deb usr/lib/s390x-linux-gnu/libc.so.6 libc-ubuntu.so.6
[[ -s libz.so.1.3.1 ]] || extract zlib1g_1.3.dfsg+really1.3.1-1+b1_s390x.deb usr/lib/s390x-linux-gnu/libz.so.1.3.1 libz.so.1.3.1
[[ -s ls ]] || extract coreutils_9.7-3_s390x.deb usr/bin/ls ls
[[ -s sort ]] || extract coreutils_9.7-3_s390x.deb usr/bin/sort sort
[[ -s busybox ]] || extract busybox-static_1.37.0-6+b9_s390x.deb usr/bin/busybox busybox
sha256sum -c - <<'SUMS'
07ec394d5e2633c99d02c0dea186d67301d352a557060e8819b3f3e40082d5d2  libc.so.6
e69b524468e091afee87cda63c24b3ab862b930cb01e956832596ef81545328f  libc-ubuntu.so.6
ab20139c62d846ead35aa4bce4642f8525e8a412649316ca1dd413aec6916f89  libz.so.1.3.1
f1f9660966895737256c82f2f0660557c9ea6de4792d85233f4e5b783101e145  ls
f81677881b4edc7bdd611151d5bfc4e326903a510537d3d5269e2e0bb7b75ffa  sort
c8bd5e687c5f97191829e7eeab1dd10a6575ea18299a9f61ee1fc63930001b57  busybox
SUMS
