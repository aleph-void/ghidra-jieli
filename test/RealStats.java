// After auto-analysis of an imported ELF: count instructions, functions, bad-instruction / error bookmarks and decompile every function.
// Script args: <summary-file> [max functions]
//@category Testing
import java.io.PrintStream;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class RealStats extends GhidraScript {
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[0]);
		int max = args.length > 1 ? Integer.parseInt(args[1]) : Integer.MAX_VALUE;
		long ins = currentProgram.getListing().getNumInstructions();
		int funcs = currentProgram.getFunctionManager().getFunctionCount();
		int bad = 0, err = 0, errCode = 0;
		var it = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (it.hasNext()) {
			var b = it.next();
			if (b.getType().getTypeString().equals("Error")) {
				err++;
				var blk = currentProgram.getMemory().getBlock(b.getAddress());
				if (blk != null && blk.isExecute()) {
					errCode++;
					out.println("CODEERROR " + b.getAddress() + " " + b.getComment());
				}
				if (err <= 8) {
					out.println("ERRORBOOKMARK " + b.getAddress() + " " + b.getCategory() + ": " + b.getComment());
				}
			}
			if (b.getType().getTypeString().equals("Bad Instruction") || b.getComment().contains("Bad Instruction") ||
				b.getComment().contains("Unable to resolve constructor")) {
				bad++;
			}
		}
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		int n = 0, failed = 0, low = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (n >= max) {
				break;
			}
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			n++;
			DecompileResults r = di.decompileFunction(f, 60, monitor);
			String c = r.getDecompiledFunction() == null ? "" : r.getDecompiledFunction().getC();
			if (!r.decompileCompleted()) {
				failed++;
				out.println("FAILED " + f.getName() + " " + f.getEntryPoint() + ": " + r.getErrorMessage());
				di.closeProgram();
				di.openProgram(currentProgram);
			}
			else if (c.contains("Low-level Error") || c.contains("Overlapping") || c.contains("Unable to") || c.contains("halt_baddata")) {
				low++;
				out.println("LOWLEVEL " + f.getName() + " " + f.getEntryPoint());
			}
		}
		out.printf("instructions %d functions %d bad-instruction-bookmarks %d error-bookmarks %d (in executable blocks %d) decompiled %d failed %d low-level %d%n",
			ins, funcs, bad, err, errCode, n, failed, low);
		out.close();
	}
}
