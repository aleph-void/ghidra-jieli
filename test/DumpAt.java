// Decode one instruction at each address of a list (no analysis): the oracle's instruction addresses.
// Script args: <addr-list file (hex, one per line)> <outfile>
// Output, one line per address: "<hex addr> <length> <text>"   (length 0 = no valid decode)
// The prototype cache is cleared after every decode (see DumpSlots.java).
//@category Testing

import java.io.*;
import java.lang.reflect.Field;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;

public class DumpAt extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		Language lang = currentProgram.getLanguage();
		Map<?, ?> protoCache = null;
		try {
			Field fld = lang.getClass().getDeclaredField("instructProtoMap");
			fld.setAccessible(true);
			protoCache = (Map<?, ?>) fld.get(lang);
		}
		catch (ReflectiveOperationException e) {
			println("warning: " + e);
		}
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String l;
			while ((l = r.readLine()) != null) {
				l = l.trim();
				if (l.isEmpty()) {
					continue;
				}
				Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseLong(l, 16));
				String text;
				int len = 0;
				try {
					ProcessorContext ctx = new ProgramProcessorContext(currentProgram.getProgramContext(), a);
					MemBuffer buf = new MemoryBufferImpl(currentProgram.getMemory(), a);
					InstructionPrototype p = lang.parse(buf, ctx, false);
					PseudoInstruction ins = new PseudoInstruction(currentProgram, a, p, buf, ctx);
					len = ins.getLength();
					text = ins.toString();
				}
				catch (Exception e) {
					text = "BAD";
				}
				out.printf("%s %d %s%n", l, len, text);
				if (protoCache != null) {
					protoCache.clear();
				}
			}
		}
		out.close();
	}
}
