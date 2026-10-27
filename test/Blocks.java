// Print the memory blocks of the program with their permissions.  Script args: [outfile]
//@category Testing
import java.io.PrintStream;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class Blocks extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		PrintStream out = a.length > 0 ? new PrintStream(a[0]) : System.out;
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			out.println(b.getName() + " " + b.getStart() + "-" + b.getEnd() + " r=" + b.isRead() + " w=" + b.isWrite() + " x=" + b.isExecute());
		}
		out.close();
	}
}
