/* ###
 * IP: Apache License 2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * s390x ELF extension: disassembles the procedure linkage table at its real entry boundaries.
 * <p>
 * Ghidra's generic PLT markup assumes a 16-byte PLT header and disassembles from .plt+16; the
 * s390x header (PLT0) and every entry are 32 bytes, so that lands in the middle of PLT0's MVC
 * and leaves a bad-instruction bookmark. Each entry is disassembled at its start and at +14
 * (the lazy-binding path the GOT slot initially points to) before the generic markup runs.
 */
public class S390_ElfExtension extends ElfExtension {

	private static final int PLT_ENTRY_SIZE = 32;
	private static final int PLT_LAZY_OFFSET = 14;

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_S390 && elf.is64Bit();
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"s390x".equals(elfLoadHelper.getProgram().getLanguage().getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_S390X";
	}

	@Override
	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		disassemblePlt(elfLoadHelper.getProgram(), monitor);
		super.processGotPlt(elfLoadHelper, monitor);
	}

	private void disassemblePlt(Program program, TaskMonitor monitor) throws CancelledException {
		MemoryBlock plt = program.getMemory().getBlock(".plt");
		if (plt == null || !plt.isExecute() || !plt.isInitialized() ||
			plt.getSize() < PLT_ENTRY_SIZE) {
			return;
		}
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, m -> {
			/* silent */ });
		long size = plt.getSize();
		for (long off = 0; off + PLT_ENTRY_SIZE <= size; off += PLT_ENTRY_SIZE) {
			monitor.checkCancelled();
			Address entry = plt.getStart().add(off);
			disassembler.disassemble(entry, null, true);
			if (off > 0) {
				disassembler.disassemble(entry.add(PLT_LAZY_OFFSET), null, true);
			}
		}
	}
}
