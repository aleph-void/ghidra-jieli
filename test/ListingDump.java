// Disassemble from an address (following flow) and print each instruction with its p-code and the context fields.
// Script args: <start-hex> <count> [outfile]
//@category Testing
import java.io.PrintStream;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class ListingDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		Address start = toAddr(Long.parseUnsignedLong(a[0], 16));
		int n = Integer.parseInt(a[1]);
		PrintStream out = a.length > 2 ? new PrintStream(a[2]) : System.out;
		new DisassembleCommand(start, null, true).applyTo(currentProgram, monitor);
		Address cur = start;
		for (int i = 0; i < n; i++) {
			Instruction ins = getInstructionAt(cur);
			if (ins == null) {
				out.println(cur + ": (none)");
				break;
			}
			out.println(cur + ": " + ins);
			for (PcodeOp op : ins.getPcode()) {
				out.println("      " + op);
			}
			cur = ins.getMaxAddress().add(1);
		}
		out.close();
	}
}
