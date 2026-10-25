#!/bin/bash
# build_zos_loaders.sh -- compile the z/OS Java loaders and install the jar
# into $GHIDRA_INSTALL_DIR/Ghidra/Processors/s390x. Re-run after any loader change.
set -e
PROJ=$(cd "$(dirname "$0")/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your ghidra_12.1.3_PUBLIC directory}"
G=$GHIDRA_INSTALL_DIR
CP=$(ls "$G"/Ghidra/Framework/*/lib/*.jar "$G"/Ghidra/Features/*/lib/*.jar | tr '\n' ':')
rm -rf "$PROJ"/loaders/build
mkdir -p "$PROJ"/loaders/build
javac -nowarn -cp "$CP" -d "$PROJ"/loaders/build \
    "$PROJ"/src/main/java/s390x/loaders/*.java
mkdir -p "$G"/Ghidra/Processors/s390x/lib
jar cf "$G"/Ghidra/Processors/s390x/lib/s390x-zos-loaders.jar \
    -C "$PROJ"/loaders/build .
echo "installed: $G/Ghidra/Processors/s390x/lib/s390x-zos-loaders.jar"
