/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.coff.relocation;

import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.coff.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class M68k_AUX_CoffRelocationHandler implements CoffRelocationHandler {

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		return fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_M68KMAGIC_AUX;
	}

	@Override
	public RelocationResult relocate(Address address, CoffRelocation relocation,
			CoffRelocationContext relocationContext)
			throws MemoryAccessException, RelocationException {

		Program program = relocationContext.getProgram();
		Memory mem = program.getMemory();
		
		int addend = mem.getInt(address);

		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (relocation.getType()) {

            case IMAGE_REL_M68K_AUX_ABS: {
                return RelocationResult.SKIPPED;
            }
            case IMAGE_REL_M68K_AUX_RELLONG: {
				// if (addend != 0) {
                // 	return RelocationResult.SKIPPED;
				// }
                int value = (int) relocationContext.getSymbolAddress(relocation)
						.add(addend)
						.getOffset();
                program.getMemory().setInt(address, value);
                break;
            }

			default: {
				return RelocationResult.UNSUPPORTED;
			}
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	/**
	 * The relocation is ignored.
	 */
	public final static short IMAGE_REL_M68K_AUX_ABS        = 0;
    public final static short IMAGE_REL_M68K_AUX_RELBYTE    = 017;
    public final static short IMAGE_REL_M68K_AUX_RELWORD    = 020;
    public final static short IMAGE_REL_M68K_AUX_RELLONG    = 021;
    public final static short IMAGE_REL_M68K_AUX_PCRBYTE    = 022;
    public final static short IMAGE_REL_M68K_AUX_PCRWORD    = 023;
    public final static short IMAGE_REL_M68K_AUX_PCRLONG    = 024;
}
