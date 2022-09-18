package rl78;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.exporter.AbstractLoaderExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

public class Rl78Exporter extends AbstractLoaderExporter {

    public Rl78Exporter() {
        super("RL78Exporter", null);
    }

    @Override
    protected boolean supportsFileFormat(String fileFormat) {
        return fileFormat.equals("");
    }

    @Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {
        if (!(domainObj instanceof Program)) {
            // impossible
            log.appendMsg("Unsupported file type");
            return false;
        }
        Program program = (Program) domainObj;
		if (!program.getLanguage().getProcessor().toString().equals("RL78")) {
			log.appendMsg("Unsupported processor");
			return false;
		}
		Memory memory = program.getMemory();
        List<FileBytes> fbytes = memory.getAllFileBytes();
        if (fbytes.isEmpty()) {
            // unexpected
            log.appendMsg("Missing file bytes, can't export");
            return false;
        }
        FileBytes bytes = fbytes.get(0);
        try (FileOutputStream os = new FileOutputStream(file)) {
            try (InputStream is = toBuffer(bytes)) {
                is.transferTo(os);
            }
        } catch (Exception e) {
            log.appendException(e);
            return false;
        }
        return true;
    }

    private static InputStream toBuffer(FileBytes bytes) {
        try {
            byte[] data = new byte[(int) bytes.getSize()];
            bytes.getModifiedBytes(0, data);
            return new ByteArrayInputStream(data);
        } catch (IOException e) {
            throw new AssertException(e);
        }
    }

}
