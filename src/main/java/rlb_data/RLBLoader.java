package rlb_data;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import rlb_data.structures.RLBInfo;

public class RLBLoader extends AbstractProgramWrapperLoader {

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		if(new BinaryReader(provider, false).readInt(0) == provider.length()) {
			loadSpecs.add(new LoadSpec(this,0,new LanguageCompilerSpecPair("DATA:BE:64:default", "pointer32"),false));
		}
		
		return loadSpecs;
	}

	@Override
	public String getName() {
		return "RLB Loader";
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		// TODO Auto-generated method stub
		BinaryReader reader = new BinaryReader(provider,false);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		RLBInfo info = new RLBInfo(reader);
		
		var filebytes = MemoryBlockUtils.createFileBytes(program, provider, info.data_offset(), info.data_size, monitor);
		
		try {
			MemoryBlockUtils.createInitializedBlock(program, false, "DATA", api.toAddr(0), filebytes, 0, filebytes.getSize(), "", "", true, false, false, log);
			
			for(int i = 0; i < info.num_relocs; ++i) {
				var data = api.createData(api.toAddr(info.pointer_locations[i]), Pointer32DataType.dataType);
				api.createMemoryReference(data, api.toAddr(reader.readInt(info.data_offset() + info.pointer_locations[i])), RefType.DATA);
			}
			
			for(int i = 0; i < info.num_entries; ++i) {
				api.createLabel(api.toAddr(info.entry_addresses[i]), info.entry_names[i], true);
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
