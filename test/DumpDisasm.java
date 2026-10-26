// Slot disassembly dump for the s390x decode test (no analysis): decodes one instruction at the
// start of every <stride>-byte slot of the program's memory with a fresh default context.
// One line per slot: "<offset-hex> <instruction-bytes-hex> <instruction text>" or "... BAD (...)".
// Script args: <outfile> [stride, default 8] [pcode|src]
//   src: print "<offset> <sinc-file>:<line>" of the matching root constructor instead
//@category Testing

import java.io.PrintStream;

import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.pcode.PcodeOp;

public class DumpDisasm extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[0]);
		int stride = args.length > 1 ? Integer.parseInt(args[1]) : 8;
		boolean pcode = args.length > 2 && args[2].equals("pcode");
		boolean src = args.length > 2 && args[2].equals("src");
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.isInitialized()) {
				continue;
			}
			Address base = block.getStart();
			for (long off = 0; off + 2 <= block.getSize(); off += stride) {
				Address a = base.add(off);
				String text, hex = "";
				PseudoInstruction ins = null;
				try {
					ProcessorContextImpl ctx = new ProcessorContextImpl(currentProgram.getLanguage());
					MemoryBufferImpl buf = new MemoryBufferImpl(currentProgram.getMemory(), a);
					InstructionPrototype p = currentProgram.getLanguage().parse(buf, ctx, false);
					ins = new PseudoInstruction(currentProgram, a, p, buf, ctx);
					text = ins.toString();
					StringBuilder h = new StringBuilder();
					for (byte b : ins.getBytes()) {
						h.append(String.format("%02x", b & 0xff));
					}
					hex = h.toString();
				}
				catch (Exception e) {
					text = "BAD (" + String.valueOf(e.getMessage()).split("\n")[0] + ")";
					hex = "-";
				}
				if (src) {
					String where = "-";
					if (ins != null && ins.getPrototype() instanceof SleighInstructionPrototype sp) {
						Constructor c = sp.getRootState().getConstructor();
						where = c.getSourceFile() + ":" + c.getLineno();
					}
					out.printf("%08x %s%n", off, where);
					continue;
				}
				out.printf("%08x %s %s%n", off, hex, text);
				if (pcode && ins != null) {
					out.printf("    flow=%s%n", ins.getFlowType());
					for (PcodeOp op : ins.getPcode()) {
						out.printf("    %s%n", op);
					}
				}
			}
		}
		out.close();
	}
}
