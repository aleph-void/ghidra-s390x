// Runs the qemu_diff.py image in Ghidra's p-code emulator and dumps its output area.
// Script args: <qd.txt> <out.bin>   (qd.txt's first line: "# stop <addr> out <addr> len <n> entry <addr>")
//@category Testing

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.pcode.Varnode;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;

public class QemuDiff extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String[] h = Files.readAllLines(Path.of(args[0])).get(0).split("\\s+");
		Address stop = toAddr(Long.decode(h[2]));
		Address out = toAddr(Long.decode(h[4]));
		int len = Integer.parseInt(h[6]);
		// "# stop <a> out <a> len <n> entry <a>": the image is imported raw at its link address
		Address entry = toAddr(Long.decode(h[8]));
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		// Instructions still modelled as pcodeops: record and continue (their results then
		// differ from QEMU and are reported per mnemonic).
		emu.registerDefaultCallOtherCallback(new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				Varnode out = op.getOutput();
				if (out != null) {
					emulate.getMemoryState().setValue(out, 0);
				}
				return true;
			}
		});
		try {
			emu.writeRegister(emu.getPCRegister(), entry.getOffset());
			emu.setBreakpoint(stop);
			emu.run(entry, null, monitor);
			if (emu.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT ||
				!emu.getExecutionAddress().equals(stop)) {
				throw new RuntimeException("did not reach " + stop + ": " +
					emu.getEmulateExecutionState() + " at " + emu.getExecutionAddress() + " " +
					emu.getLastError());
			}
			try (FileOutputStream f = new FileOutputStream(args[1])) {
				f.write(emu.readMemory(out, len));
			}
		}
		finally {
			emu.dispose();
		}
	}
}
