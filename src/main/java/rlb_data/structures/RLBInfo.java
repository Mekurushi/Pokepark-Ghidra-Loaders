package rlb_data.structures;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.util.bin.BinaryReader;

public class RLBInfo {
	public int file_size;
	public int data_size;
	public int num_relocs;
	public int num_entries;
	public int num_other_entries;
	
	public long[] pointer_locations;
	public final Set<Long> relocationSet;

	public long[] entry_addresses;
	public String[] entry_names;
	
	public RLBInfo(BinaryReader reader) throws IOException {
		file_size = reader.readNextInt();
		data_size = reader.readNextInt();
		num_relocs = reader.readNextInt();
		num_entries = reader.readNextInt();
		num_other_entries = reader.readNextInt();
		
		pointer_locations = new long[num_relocs];
		relocationSet = new HashSet<>();
		reader.setPointerIndex(reloc_offset());
		for(int i = 0; i < num_relocs; i++) {
			long loc = reader.readNextInt();
			pointer_locations[i] = loc;
			relocationSet.add(loc);
		}
		
		entry_addresses = new long[num_entries];
		entry_names = new String[num_entries];
		for(int i = 0; i < num_entries; ++i) {
			int address = reader.readNextInt();
			int offset = reader.readNextInt();
			long strings = strings_offset();
			entry_names[i] = reader.readAsciiString(strings+offset);
			entry_addresses[i] = address;
		}
	}
	
	public long data_offset() {
		return 0x20;
	}
	
	public long reloc_offset() {
		return data_offset() + data_size;
	}
	
	public long entries_offset() {
		return reloc_offset() + num_relocs*4;
	}
	
	public long strings_offset() {
		return entries_offset() + (num_entries + num_other_entries)*8;
	}
}
