#!/bin/bash
# build_elf_reloc.sh -- compile the s390x ELF relocation handler and install
# the jar into $GHIDRA_INSTALL_DIR/Ghidra/Processors/s390x. Re-run after any change.
# The handler is discovered automatically by Ghidra's ClassSearcher
# (ExtensionPoint); no registration file is needed.
set -e
PROJ=$(cd "$(dirname "$0")/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your ghidra_12.1.3_PUBLIC directory}"
G=$GHIDRA_INSTALL_DIR
CP=$(ls "$G"/Ghidra/Framework/*/lib/*.jar "$G"/Ghidra/Features/*/lib/*.jar | tr '\n' ':')
rm -rf "$PROJ"/loaders/build-elfreloc
mkdir -p "$PROJ"/loaders/build-elfreloc
javac -nowarn -cp "$CP" -d "$PROJ"/loaders/build-elfreloc \
    "$PROJ"/src/main/java/ghidra/app/util/bin/format/elf/relocation/*.java
mkdir -p "$G"/Ghidra/Processors/s390x/lib
jar cf "$G"/Ghidra/Processors/s390x/lib/s390x-elf-reloc.jar \
    -C "$PROJ"/loaders/build-elfreloc .
echo "installed: $G/Ghidra/Processors/s390x/lib/s390x-elf-reloc.jar"
unzip -l "$G"/Ghidra/Processors/s390x/lib/s390x-elf-reloc.jar | grep class
