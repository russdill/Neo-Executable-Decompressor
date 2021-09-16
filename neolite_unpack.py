#!/usr/bin/python3

# Copyright Russ Dill, 2021. russ.dill@gmail.com

# Uses the data header provided by neolite to attempt to reconstruct the
# original DLL, or at least a workable version.

import sys
import pefile
import struct
import zlib

def fixup(data):
    pe = pefile.PE(data=data)

    # Find where actual pe data ends
    file_end = 0
    raw_start = len(data)
    for section in pe.sections:
        if section.PointerToRawData:
            file_end = max(section.PointerToRawData + section.SizeOfRawData, file_end)
            raw_start = min(section.PointerToRawData, raw_start)

    # The data neolite tacks onto the file
    ndata = data[file_end:]

    # Read and validate header
    header = struct.unpack_from('<21I', ndata)
    if header[0] != 0x4181996:
        raise Exception('Did not find neolite magic value')
        
    # Get header info
    section_info_count = header[7]
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = header[8]
    imports_offset = header[9]
    iat_offset = header[10]
    iat_sz = header[11]
    reloc_usize = header[12]
    reloc_csize = header[13]
    tls_data = header[17]

    if tls_data:
        raise Exception('tls data fixup currently not handled')

    # Parse the neolite section info
    section_info_list = []
    total_compressed = reloc_csize
    for s in struct.iter_unpack('<IIII', ndata[0x54:0x54+0x10*section_info_count]):
        info = {'idx': s[0], 'flags': s[1], 'usize': s[2], 'csize': s[3]}
        total_compressed += info['csize']
        section_info_list.append(info)


    # Decompress the stored section data
    compressed_start = len(ndata) - total_compressed
    pos = compressed_start
    section_info = {}
    for info in section_info_list:
        decompress = zlib.decompressobj(-zlib.MAX_WBITS)
        data = decompress.decompress(ndata[pos+2:pos+info['csize']])
        data += decompress.flush()
        if len(data) != info['usize']:
            raise Exception
        info['data'] = data
        pos += info['csize']
        section_info[info['idx']] = info

    # Decompress the relocation data
    decompress = zlib.decompressobj(-zlib.MAX_WBITS)
    reloc_data = decompress.decompress(ndata[pos+2:pos+reloc_csize])
    reloc_data += decompress.flush()
    if len(reloc_data) != reloc_usize:
        raise Exception

    # Perform surgery on the sections
    raw_offset = raw_start
    new_data = bytearray(pe.__data__[:raw_start])
    new_sections = []
    sections_offset = pe.sections[0].get_file_offset()
    reloc_section = None

    pe.OPTIONAL_HEADER.SizeOfCode = 0
    pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
    pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0
    found_code = False
    found_data = False
    for section_idx, section in enumerate(pe.sections):
        # Trash these neolit appended sections
        if section.Name.rstrip(b'\0') in (b'.neolit', b'.reloc'):
            pe.__structures__.remove(section)
            continue

        section.set_file_offset(sections_offset + section.sizeof() * len(new_sections))

        if section.Name.rstrip(b'\0') == b'Oreloc':
            name = bytearray(section.Name)
            name[0:1] = b'.'
            section.Name = bytes(name)
            reloc_section = section

        info = section_info.get(section_idx, None)
        if info:
            data = info['data']
            flags = info['flags']
            section.Characteristics = flags
        elif section.PointerToRawData:
            data = section.get_data()
        else:
            data = None

        if section.IMAGE_SCN_CNT_CODE:
            pe.OPTIONAL_HEADER.SizeOfCode += section.Misc
            if not found_code:
                pe.OPTIONAL_HEADER.BaseOfCode = section.VirtualAddress
                found_code = True
        elif section.IMAGE_SCN_CNT_INITIALIZED_DATA:
            pe.OPTIONAL_HEADER.SizeOfInitializedData += section.Misc
            if not found_data:
                pe.OPTIONAL_HEADER.BaseOfData = section.VirtualAddress
                found_data = True
        elif section.IMAGE_SCN_CNT_UNINITIALIZED_DATA:
            pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.Misc

        if data is None:
            continue

        #section.IMAGE_SCN_CNT_UNINITIALIZED_DATA = False
        #section.IMAGE_SCN_CNT_INITIALIZED_DATA = True
        #section.IMAGE_SCN_MEM_EXECUTE = True
        #section.IMAGE_SCN_MEM_WRITE = False
        #section.IMAGE_SCN_CNT_CODE = True

        if len(data) > section.SizeOfRawData:
            raise Exception

        raw_offset = pe.adjust_FileAlignment(raw_offset, pe.OPTIONAL_HEADER.FileAlignment)
        if raw_offset > len(new_data):
            new_data += b'\0' * (len(new_data) - raw_offset)
        new_data += data
        section.PointerToRawData = raw_offset
        raw_offset += section.SizeOfRawData
        new_sections.append(section)


    # Fixup data directory 1, Import table
    n = imports_offset
    imports_size = None
    imports_end = 0
    for n in range(imports_offset, len(new_data), 20):
        if new_data[n:n+20] == bytes(20):
            imports_size = n+20 - imports_offset
            imports_end = max(imports_end, n+20)
            break
        else:
            orig = int.from_bytes(new_data[n:n+4], 'little')
            for o in range(orig, len(new_data), 4):
                by_name = int.from_bytes(new_data[o:o+4], 'little')
                if not by_name:
                    imports_end = max(imports_end, o+4)
                    break
                if by_name & 0x80000000 == 0:
                    end = new_data.find(b'\0', by_name+2)
                    if end == -1:
                        raise Exception
                    imports_end = max(imports_end, end+1)
            name = int.from_bytes(new_data[n+12:n+16], 'little')
            end = new_data.find(b'\0', name)
            if end == -1:
                raise Exception
            imports_end = max(imports_end, end+1)
    imports_end -= imports_end % -16

    if imports_size is None:
        raise Exception
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = imports_offset
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = imports_size

    # Put the exports table at the end of the imports table. This is a bit of an
    # assumption and may not always hold.
    start = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
    sz = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
    export_data = bytearray(pe.get_data(start, sz))
    if new_data[imports_end:imports_end+sz] != bytes(sz):
        raise Exception('Could not find free space for exports table')

    # Relocate addresses
    for i in (0xc, 0x1c, 0x20, 0x24):
        v = int.from_bytes(export_data[i:i+4], 'little')
        v += imports_end - start
        export_data[i:i+4] = v.to_bytes(4, 'little')

    names = int.from_bytes(export_data[0x20:0x24], 'little') - imports_end
    name_count = int.from_bytes(export_data[0x18:0x1c], 'little')
    for i in range(names, names+name_count*4, 4):
        v = int.from_bytes(export_data[i:i+4], 'little')
        v += imports_end - start
        export_data[i:i+4] = v.to_bytes(4, 'little')

    new_data[imports_end:imports_end+sz] = export_data
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress = imports_end


    # Translate relocs from neolite format and fixup reloc data directory
    address = 0
    page = None
    relocs = b''
    curr_relocs = None
    n = 0
    while n < len(reloc_data):
        reloc_type = reloc_data[n]
        if reloc_type == 0:
            address += int.from_bytes(reloc_data[n+1:n+3], 'little') + 0x101
            n += 3
        elif reloc_type == 1:
            address += int.from_bytes(reloc_data[n+1:n+4], 'little') + 0x10100
            n += 4
        elif reloc_type == 2:
            address += int.from_bytes(reloc_data[n+1:n+5], 'little')
            n += 5
        else:
            address += reloc_type + 1
            n += 1
        if address // 4096 != page:
            if curr_relocs:
                relocs += struct.pack('<II', page * 4096, len(curr_relocs) + 8)
                relocs += curr_relocs
            page = address // 4096
            curr_relocs = b''
        curr_relocs += struct.pack('<H', (address - page * 4096) | (3 << 12))

    if curr_relocs:
        relocs += struct.pack('<II', page * 4096, len(curr_relocs) + 8)
        relocs += curr_relocs

    if len(relocs) > reloc_section.SizeOfRawData:
        raise Exception(f'Reloc section ({reloc_section.SizeOfRawData}) too small to fit relocs ({len(relocs)})')

    roffset = reloc_section.PointerToRawData
    if new_data[roffset:roffset+len(relocs)] != bytes(len(relocs)):
        raise Exception('Existing data where we thought we should put the relocs')

    new_data[roffset:roffset+len(relocs)] = relocs

    pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress = reloc_section.VirtualAddress
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = len(relocs)

    # Fixup IAT
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress = iat_offset
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].Size = iat_sz

    # apply changes
    pe.__data__ = bytes(new_data)
    pe.FILE_HEADER.NumberOfSections = len(new_sections)
    pe.sections = new_sections
    return pe.write()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('Usage: neolite_unpack.py [input dll] [output dll]')
        sys.exit(1)
    data = open(sys.argv[1], 'rb').read()
    open(sys.argv[2], 'wb').write(fixup(data))

