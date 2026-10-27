// Decompile the function containing an address and print the C code.  Script args: <address-hex> [outfile]
//@category Testing
import java.io.PrintStream;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DecompAt extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		PrintStream out = a.length > 1 ? new PrintStream(a[1]) : System.out;
		Function f = getFunctionContaining(toAddr(Long.parseUnsignedLong(a[0], 16)));
		if (f == null) {
			out.println("no function at " + a[0]);
			return;
		}
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		var r = di.decompileFunction(f, 60, monitor);
		out.println(r.getDecompiledFunction() == null ? r.getErrorMessage() : r.getDecompiledFunction().getC());
		out.close();
	}
}
