from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from decompnet.reference_metadata import MAX_IMPORT_BYTES, parse_metadata


@pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None, reason="needs a Java compiler/runtime"
)
def test_ghidra_export_helper_bounds_utf8_output_and_addresses(tmp_path):
    source_root = Path(__file__).parents[1] / "src/decompnet/forks/ghidra_scripts"
    script = source_root / "ExportReferenceMetadata.java"
    packages = {
        "ghidra/app/script/GhidraScript.java": """package ghidra.app.script;
import java.io.File;
import ghidra.program.model.listing.Program;
public abstract class GhidraScript {
 public Program currentProgram; public Monitor monitor = new Monitor();
 public File askFile(String title, String button) { return new File(System.getProperty("export.file")); }
 public void println(String text) { System.out.println(text); }
 public abstract void run() throws Exception;
 public static class Monitor { public boolean isCancelled() { return false; } }
}""",
        "ghidra/program/model/address/Address.java": """package ghidra.program.model.address;
public class Address {
 private final String value; private final boolean memory;
 public Address(String value, boolean memory) { this.value=value; this.memory=memory; }
 public boolean isMemoryAddress() { return memory; }
 public String toString() { return value; }
}""",
        "ghidra/program/model/listing/DataType.java": """package ghidra.program.model.listing;
public class DataType { private final String name; public DataType(String n) { name=n; }
 public String getName() { return name; } }""",
        "ghidra/program/model/listing/Parameter.java": """package ghidra.program.model.listing;
public class Parameter { public DataType getDataType() { return new DataType("int"); }
 public String getName() { return "arg"; } }""",
        "ghidra/program/model/listing/Function.java": """package ghidra.program.model.listing;
import java.util.*; import ghidra.program.model.address.Address;
public class Function {
 private final Address address; private final String name, comment;
 public Function(Address a, String n, String c) { address=a; name=n; comment=c; }
 public Address getEntryPoint() { return address; } public String getName() { return name; }
 public DataType getReturnType() { return new DataType("int"); }
 public List<Parameter> getParameters() { return Collections.singletonList(new Parameter()); }
 public boolean hasVarArgs() { return false; } public String getComment() { return comment; }
}""",
        "ghidra/program/model/listing/FunctionIterator.java": """package ghidra.program.model.listing;
import java.util.*;
public class FunctionIterator implements Iterator<Function> {
 private final Iterator<Function> iterator; public FunctionIterator(List<Function> f) { iterator=f.iterator(); }
 public boolean hasNext() { return iterator.hasNext(); } public Function next() { return iterator.next(); }
}""",
        "ghidra/program/model/listing/FunctionManager.java": """package ghidra.program.model.listing;
import java.util.*;
public class FunctionManager { private final List<Function> f; public FunctionManager(List<Function> f) { this.f=f; }
 public FunctionIterator getFunctions(boolean forward) { return new FunctionIterator(f); } }""",
        "ghidra/program/model/listing/Program.java": """package ghidra.program.model.listing;
import java.util.*;
public class Program { private final FunctionManager manager; public Program(List<Function> f) { manager=new FunctionManager(f); }
 public FunctionManager getFunctionManager() { return manager; } }""",
        "TestRunner.java": """import java.util.*; import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
public class TestRunner extends ExportReferenceMetadata {
 public static void main(String[] args) throws Exception {
  List<Function> functions=new ArrayList<>();
  functions.add(new Function(new Address("ram:FFFFFFFFFFFFFFFF", true), "u64", "comment"));
  functions.add(new Function(new Address("ram:0000000000000001", true), "one", "comment"));
  functions.add(new Function(new Address("register:0", false), "no_space", "comment"));
  functions.add(new Function(new Address("x".repeat(140), false), "long_id", "comment"));
  for (int i=0;i<700;i++) functions.add(new Function(new Address(String.format("ram:%08X", i+2), true),
      i==0 ? "n".repeat(300) : "fn"+i, "c".repeat(5000)));
  TestRunner script=new TestRunner(); script.currentProgram=new Program(functions); script.run();
 }
}""",
    }
    for relative, text in packages.items():
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    harness_script = tmp_path / "ExportReferenceMetadata.java"
    harness_script.write_bytes(script.read_bytes())
    sources = [str(path) for path in tmp_path.rglob("*.java")]
    classes = tmp_path / "classes"
    classes.mkdir()
    subprocess.run(["javac", "-d", str(classes), *sources], check=True, capture_output=True, text=True, timeout=120)
    output = tmp_path / "export.json"
    run = subprocess.run(
        ["java", "-Dexport.file=" + str(output), "-cp", str(classes), "TestRunner"],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    raw = output.read_bytes()
    assert len(raw) <= MAX_IMPORT_BYTES
    assert "2 MiB" in run.stdout and "shortened" in run.stdout
    meta, records = parse_metadata(raw)
    assert meta == {"kind": "ghidra", "build": None}
    assert records[0]["address"] == 0xFFFFFFFFFFFFFFFF
    assert records[1]["address"] == 1
    assert records[2]["address"] is None
    assert len(records[3]["id"]) <= 128
    assert len(records) < 703
