// Export user-reviewed symbol metadata from a Ghidra program; decompdecomp never invokes this script.
// @category Export
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;

public class ExportReferenceMetadata extends GhidraScript {
    private static final int MAX_RECORDS = 2000;
    private static final int MAX_FILE_BYTES = 2 * 1024 * 1024;
    private static final BigInteger MAX_UNSIGNED_ADDRESS = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
    private static final String PREFIX = "{\n  \"schema\": \"decompdecomp.reference-metadata\",\n" +
        "  \"version\": 1,\n  \"kind\": \"ghidra\",\n  \"build\": null,\n  \"records\": [\n";
    private static final String SUFFIX = "  ]\n}\n";

    private String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c == '\n') out.append("\\n");
            else if (c == '\r') out.append("\\r");
            else if (c == '\t') out.append("\\t");
            else if (c >= 0x20) out.append(c);
        }
        return out.append('"').toString();
    }

    private String bounded(String text, int limit) {
        if (text == null) return "";
        return text.length() <= limit ? text : text.substring(0, limit);
    }

    private String externalId(String address) throws Exception {
        String id = "function-" + address;
        if (id.length() <= 128) return id;
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(address.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder("function-");
        for (byte b : digest) hex.append(String.format("%02x", b & 0xff));
        return hex.toString();
    }

    private String addressJson(Address address) {
        if (!address.isMemoryAddress()) return "null";
        String rendered = address.toString();
        int colon = rendered.lastIndexOf(':');
        String offset = colon < 0 ? rendered : rendered.substring(colon + 1);
        if (!offset.matches("[0-9a-fA-F]+") || offset.length() > 16) return "null";
        BigInteger value = new BigInteger(offset, 16);
        if (value.signum() < 0 || value.compareTo(MAX_UNSIGNED_ADDRESS) > 0) return "null";
        return quote("0x" + value.toString(16).toUpperCase());
    }

    private String signature(Function function) {
        StringBuilder signature = new StringBuilder(function.getReturnType().getName()).append(" ")
            .append(function.getName()).append("(");
        int count = 0;
        for (Parameter parameter : function.getParameters()) {
            if (count++ > 0) signature.append(", ");
            signature.append(parameter.getDataType().getName()).append(" ").append(parameter.getName());
        }
        if (function.hasVarArgs()) {
            if (count > 0) signature.append(", ");
            signature.append("...");
        }
        return signature.append(")").toString();
    }

    private String record(Function function) throws Exception {
        Address entry = function.getEntryPoint();
        String externalAddress = entry.toString();
        String name = bounded(function.getName(), 256);
        String fullSignature = signature(function);
        String comment = function.getComment();
        return "{\"id\":" + quote(externalId(externalAddress)) +
            ",\"kind\":\"function\",\"name\":" + quote(name) +
            ",\"address\":" + addressJson(entry) +
            ",\"unit\":\"\",\"signature\":" + quote(bounded(fullSignature, 1024)) +
            ",\"comment\":" + quote(bounded(comment == null ? "" : comment, 4096)) +
            ",\"pseudocode\":\"\"}";
    }

    private int utf8Bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    @Override
    public void run() throws Exception {
        File output = askFile("Export reference metadata", "Save");
        List<String> records = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int outputBytes = utf8Bytes(PREFIX) + utf8Bytes(SUFFIX);
        boolean fieldTruncated = false;
        boolean byteLimited = false;
        while (functions.hasNext() && records.size() < MAX_RECORDS && !monitor.isCancelled()) {
            Function function = functions.next();
            String encoded = record(function);
            String line = "    " + encoded + ",\n";
            if (outputBytes + utf8Bytes(line) > MAX_FILE_BYTES) {
                byteLimited = true;
                break;
            }
            outputBytes += utf8Bytes(line);
            records.add(encoded);
            fieldTruncated |= function.getName().length() > 256 || signature(function).length() > 1024 ||
                function.getComment() != null && function.getComment().length() > 4096;
        }
        StringBuilder json = new StringBuilder(PREFIX);
        for (int i = 0; i < records.size(); i++) {
            json.append("    ").append(records.get(i));
            if (i + 1 < records.size()) json.append(',');
            json.append('\n');
        }
        json.append(SUFFIX);
        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_FILE_BYTES) throw new IOException("Metadata output exceeded its byte budget.");
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.UTF_8)) {
            writer.write(json.toString());
        }
        println("Exported " + records.size() + " functions (" + bytes.length + " UTF-8 bytes).");
        if (byteLimited) println("Stopped at the 2 MiB JSON budget; import the partial export and rerun for remaining functions.");
        if (records.size() == MAX_RECORDS && functions.hasNext()) println("Stopped at the 2,000-record limit.");
        if (monitor.isCancelled()) println("Export was cancelled; the bounded partial export was saved.");
        if (fieldTruncated) println("Some names, signatures, or comments were shortened to the schema field limits.");
        println("Build identity is unknown. Review every target mapping explicitly.");
    }
}
