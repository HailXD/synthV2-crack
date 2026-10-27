import java.io.FileInputStream;
import java.nio.file.Path;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class TraceLicense extends GhidraScript {
    private static final Path DATA_PATH = Path.of("C:/Program Files/Synthesizer V Studio 2 Pro/.analysis/rdata.bin");
    private static final long IMAGE_BASE = 0x140000000L;
    private static final long DATA_RVA = 0x11fb000L;
    private static final long[] TARGETS = {0xeb5c0L, 0x102df0L, 0x198580L, 0x1a1c70L};
    private static final int TIMEOUT_SECONDS = 60;

    @Override
    public void run() throws Exception {
        if (currentProgram.getMemory().getBlock("rdata") == null) {
            try (FileInputStream stream = new FileInputStream(DATA_PATH.toFile())) {
                MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
                    "rdata", toAddr(IMAGE_BASE + DATA_RVA), stream,
                    DATA_PATH.toFile().length(), monitor, false
                );
                block.setWrite(false);
                block.setExecute(false);
            }
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            for (long rva : TARGETS) {
                disassemble(toAddr(IMAGE_BASE + rva));
                Function function = getFunctionAt(toAddr(IMAGE_BASE + rva));
                if (function == null) {
                    function = createFunction(toAddr(IMAGE_BASE + rva), "FUN_" + Long.toHexString(rva));
                }
                System.out.println("FUNCTION_RVA " + Long.toHexString(rva));
                if (function == null) {
                    System.out.println("Function discovery failed");
                    continue;
                }
                var result = decompiler.decompileFunction(function, TIMEOUT_SECONDS, monitor);
                if (result.decompileCompleted()) {
                    System.out.println(result.getDecompiledFunction().getC());
                } else {
                    System.out.println(result.getErrorMessage());
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
