package rlb_data.structures;

import java.io.IOException;
import java.util.Set;
import java.util.function.LongPredicate;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;

public class ScriptListTableEntry {
	public static final int SIZE = 0x44;
	public static final Set<String> TABLE_NAMES = Set.of("BackFromAttractionScriptList", "CheckObjectScriptList",
			"EnterZoneScriptList", "HitDashScriptList", "HitThunderboltScriptList", "ReplaceScriptList",
			"TimeOutScriptList", "TouchAreaScriptList");

	public static StructureDataType create(DataTypeManager dtm) {
		StructureDataType s = new StructureDataType(new CategoryPath("/RLB"), "ScriptListTableEntry", 0, dtm);

		PointerDataType ptr32 = new Pointer32DataType();
		DataType int32 = IntegerDataType.dataType;

		s.add(ptr32, 4, "name_ptr", null);
		s.add(int32, 4, "object_id", null);
		s.add(int32, 4, "minimum_chapter", null);
		s.add(int32, 4, "medium_chapter", null);
		s.add(int32, 4, "maximum_chapter", null);
		s.add(ptr32, 4, "flagname_ptr", null);
		s.add(int32, 4, "flag_value_condition", null);
		s.add(ByteDataType.dataType, 1, "target_script", null); // index of the FsbFileListData table
		s.add(ByteDataType.dataType, 3, "pad_0x1d", null);
		s.add(int32, 4, "unknown", null);
		s.add(ptr32, 4, "entrypoint_ptr", null);
		s.add(int32, 4, "zone_id", null);
		s.add(int32, 4, "area_id", null);
		s.add(int32, 4, "position_id", null);
		s.add(int32, 4, "pad_0x34", null);
		s.add(ptr32, 4, "after_script_entrypoint_ptr", null);
		s.add(ptr32, 4, "animation_ptr", null);
		s.add(ptr32, 4, "flagname2_ptr", null);

		return s;
	}

	/**
	 * Counts how many {@link ScriptListTableEntry#SIZE}-sized records exist
	 * starting at {@code tableAddr}, including the terminating entry. 
	 * The terminating entry uses in target_script the index of the terminating entry of FsbFileListData
	 */
	public static int countEntriesUntilZeroTerminated(BinaryReader reader, long dataOffset, long tableAddr, LongPredicate isRelocated)
			throws IOException {

		int count = 0;
		long fileOffset = dataOffset + tableAddr;
		long fileLength = reader.length();

		while(fileOffset + SIZE <= fileLength) {
	        long namePtrAddress = fileOffset - dataOffset;
	        int namePtr = reader.readInt(fileOffset);
	        count++;
	        if(namePtr == 0 && !isRelocated.test(namePtrAddress)) {
	            break;
	        }
	        fileOffset += SIZE;
	    }

		return count;
	}
}