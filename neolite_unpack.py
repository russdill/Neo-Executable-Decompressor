#!/usr/bin/python3

# Copyright Russ Dill, 2021-2023. russ.dill@gmail.com

# Uses the data header provided by neolite to attempt to reconstruct the
# original DLL, or at least a workable version.

import sys
import pefile
import struct
import zlib

def hexdump(src, length=16, sep='.'):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    last_chars = None
    was_continue = False
    for c in range(0, len(src), length):
        chars = src[c: c + length]
        hex_ = ' '.join([f'{x:02x}' for x in chars])
        if len(hex_) > 24:
            hex_ = ' '.join([hex_[:24], hex_[24:]])
        printable = ''.join([str((x <= 127 and FILTER[x]) or sep) for x in chars])
        if chars == last_chars:
            if not was_continue:
                lines.append('*')
                was_continue = True
        else:
            lines.append(f'{c:08x}  {hex_:{length*3}}  |{printable:{length}}|')
            was_continue = False
        last_chars = chars
    if was_continue:
        c = len(src) - (len(src) % -length)
        lines.append(f'{c:08x}')
    return '\n'.join(lines)

header_entries = [
    'magic',
    'unknown_04',
    'zlib_text_offset',
    'zlib_text_usize',
    'zlib_data_offset',
    'zlib_data_usize',
    'zlib_relocations_sz',
    'section_info_count',
    'orig_entry',
    'imports_offset',
    'iat_offset',
    'iat_sz',
    'reloc_usize',
    'reloc_csize',
    'use_zlib',
    'resource_section_idx',
    'resource_offset',
    'tls_data',
    'image_size',
    'extra_data_usize',
    'extra_data_csize',
]

info_entries = [
    'idx',
    'flags',
    'usize',
    'csize',
]

sub_header_entries = [
    'image_base',
    'original_file_size',
    'image_size',
    'zlib_csize',
    'fixup_rsrc_count',
    'fixup_rsrc_csize',
    'fixup_patch_csize',
    'fixup_data_csize',
    'flags',
    'section_count',
]

class neolite_info:
    def __init__(self, data):
       self.__dict__.update(zip(info_entries, struct.unpack_from('<4I', data)))

class neolite_sub_header:
    def __init__(self, data, offset):
        self.header_offset = offset
        self.__dict__.update(zip(sub_header_entries, struct.unpack_from('<8IHH', data, offset)))
        offset += 4*9
        self.sections = struct.unpack_from(f'<{self.section_count}I', data, offset)
        offset += self.section_count * 4
        self.header_size = offset - self.header_offset

class neolite_header:
    def __init__(self, data, offset):
        self.header_offset = offset
        self.__dict__.update(zip(header_entries, struct.unpack_from('<21I', data, offset)))
        offset += 4*21
        self.sections = [neolite_info(data[n:n+16]) for n in range(offset, offset+16*self.section_info_count, 16)]
        offset += 16*self.section_info_count
        self.header_size = offset - self.header_offset

class Neocomp:
    def read_offset(self):
        self.pos += 1
        return self.b[self.pos - 1]

    def read_command(self):
        if not self.command_word:
            d = int.from_bytes(self.b[self.pos:self.pos+4], 'little')
            self.pos += 4
            self.command_word = [(d >> n) & 0xf for n in range(0, 32, 4)]
        return self.command_word.pop(0)

    def read_flag(self):
        if not self.flag_word:
            d = int.from_bytes(self.b[self.pos:self.pos+4], 'little')
            self.pos += 4
            self.flag_word = [(d >> n) & 1 for n in range(0, 32)]
        return self.flag_word.pop(0)

    def back(self, b, n):
        w = self.offsets[-(b + 1)]
        self.offsets.append(len(self.out))
        if w == len(self.out) - 1:
            self.out += bytes([self.out[-1]] * n)
        else:
            while n:
                x = min(n, len(self.out) - w)
                self.out += self.out[w:w + n]
                n -= x
                w += x

    def copy_literals(self, n):
        self.offsets.extend(range(len(self.out), len(self.out) + n))
        self.out += self.b[self.pos:self.pos + n]
        self.pos += n

    def terminate(self):
        self.done = True

    def back_base(self, offset, n):
        self.back(self.read_offset() + offset, n)

    def back_extend16(self, n):
        offset = self.read_command()
        if offset == 0:
            offset = self.read_command() + 16
        self.back_base(offset * 256, n)

    def back_offset0(self, n):
        if self.read_flag():
            self.back_extend16(n)
        else:
            self.back_base(0, n)

    def next_command(self):
        match self.read_command():
            case 0: self.back_base(0, 3)
            case 1: self.back_base(0, 4)
            case 2: self.back_base(0, 5)
            case 3: self.back_base(256, 3)
            case 4:
                command = self.read_command()
                if command < 2:
                    self.back(0, command + 3)
                else:
                    self.back_base(command * 256, 3)
            case 5: self.back_extend16(4)
            case 6: self.back_extend16(5)
            case 7: self.back_offset0(6)
            case 8: self.back_offset0(self.read_flag() + 7)
            case 9: self.back_offset0(self.read_flag() * 2 + self.read_flag() + 9)
            case 10: self.copy_literals(1)
            case 11: self.copy_literals(2)
            case 12: self.copy_literals(self.read_flag() + 3)
            case 13: self.copy_literals(self.read_flag() * 2 + self.read_flag() + 5)
            case 14: self.copy_literals(self.read_command() + 9)
            case 15:
                if self.read_flag():
                    if self.read_flag():
                        offset = self.read_offset()
                        if offset == 255:
                            self.terminate()
                        else:
                            self.back_offset0(offset + 29)
                    else:
                        self.copy_literals(self.read_offset() + 25)
                else:
                    self.back_offset0(self.read_command() + 13)

    def reset(self):
        self.done = False
        self.command_word = []
        self.flag_word = []
        self.offsets = []

    def unpack(self, b, offset=0, csize=None, usize=None):
        csize = len(b) if csize is None else csize
        self.pos = offset
        self.out = bytearray()
        self.b = b
        while self.pos < csize and (usize is None or len(self.out) < usize):
            code_word = int.from_bytes(self.b[self.pos:self.pos + 2], 'little')
            self.pos += 2
            if code_word & 0x8000:
                chunk_csize = code_word - 0x8000
                self.reset()
                orig_pos = self.pos
                while not self.done:
                    self.next_command()
                    assert self.pos - orig_pos <= chunk_csize
                assert self.pos - orig_pos == chunk_csize
            else:
                self.out += self.b[self.pos:self.pos + code_word + 1]
                self.pos += code_word + 1
        if usize is not None and len(self.out) < usize:
            self.out += bytes(usize - len(self.out))

        return self.out, self.pos

def neo_uncompress_loose(data, usize):
    return Neocomp().unpack(data, usize=usize)

def neo_uncompress(data, usize):
    ret, n = Neocomp().unpack(data, usize=usize)

    if len(ret) != usize:
        raise Exception(f'{len(ret)=:x} {usize=:x}')

    if n != len(data):
        raise Exception(f'{len(data)=:x} {n=:x}')

    return ret

def zlib_uncompress(data, usize):
    obj = zlib.decompressobj()
    ret = obj.decompress(data, max_length=usize)
    ret += obj.flush()

    if len(ret) > usize:
        raise Exception(f'{len(ret)=:x} {usize=:x}')

    if not obj.eof:
        raise Exception

    return ret


def is_neolite(data):
    pe = pefile.PE(data=data)

    rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + 0x15
    section = pe.get_section_by_rva(rva)
    offset = rva - section.get_VirtualAddress_adj() + section.PointerToRawData
    hdr_offset = int.from_bytes(data[offset:offset+4], 'little')

    if len(data) - hdr_offset < 84:
        return False

    hdr = neolite_header(data, hdr_offset)
    return hdr.magic in (0x4181996, 0x14181996)

def print_info(data):
    pe = pefile.PE(data=data)

    rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + 0x15
    section = pe.get_section_by_rva(rva)
    offset = rva - section.get_VirtualAddress_adj() + section.PointerToRawData
    hdr_offset = int.from_bytes(data[offset:offset+4], 'little')

    hdr = neolite_header(data, hdr_offset)
    if hdr.magic not in (0x4181996, 0x14181996):
        raise Exception(f'Did not find neolite magic value ({hdr.magic=:08x})')

    reversible = hdr.magic == 0x14181996

    for key, val in hdr.__dict__.items():
        if key in ('sections'):
            continue
        key += ':'
        v = f'0x{val:x}'
        print(f'{key:22} {v:>10}')

    section_info = {}
    for info in hdr.sections:
        section_info[info.idx] = info

    print()
    for section_idx, section in enumerate(pe.sections):
        print(section)
        info = section_info.get(section_idx, None)
        if info:
            for key, val in info.__dict__.items():
                key += ':'
                v = f'0x{val:x}'
                print(f'{key:7} {v:>10}')
        if section_idx == hdr.resource_section_idx:
            print(f'Neolite data offset: 0x{hdr.resource_offset:x}')
        print()

    if reversible:
        rev_hdr = neolite_sub_header(data, hdr.header_offset+hdr.header_size)
        for key, val in rev_hdr.__dict__.items():
            if key in ('sections'):
                continue
            key += ':'
            v = f'0x{val:x}'
            print(f'rev.{key:22} {v:>10}')
        key = 'offset:'
        for val in rev_hdr.sections:
            v = f'0x{val:x}'
            print(f'rev.{key:22} {v:>10}')

def fixup(data):
    pe = pefile.PE(data=data)

    # Find where actual pe data ends
    file_end = 0
    raw_start = len(data)
    for section in pe.sections:
        if section.PointerToRawData:
            file_end = max(section.PointerToRawData + section.SizeOfRawData, file_end)
            raw_start = min(section.PointerToRawData, raw_start)

    # Read and validate header
    rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + 0x15
    section = pe.get_section_by_rva(rva)
    offset = rva - section.get_VirtualAddress_adj() + section.PointerToRawData
    hdr_offset = int.from_bytes(data[offset:offset+4], 'little')

    pos = hdr_offset
    hdr = neolite_header(data, pos)
    pos += hdr.header_size

    if hdr.magic not in (0x14181996, 0x4181996):
        raise Exception(f'Did not find neolite magic value ({hdr.magic=:08x})')

    reversible = hdr.magic == 0x14181996
    if reversible:
        rev_hdr = neolite_sub_header(data, pos)
        pos += rev_hdr.header_size

    if reversible:
        # The fixup data comes first, but it might be compressed with zlib,
        # so we have to move forward and get zlib.
        zpos_start = rev_hdr.fixup_data_csize + rev_hdr.header_offset
    else:
        zpos_start = pos

    zpos = zpos_start
    if hdr.use_zlib:
        # Decompress the included decompressor. It's just zlib, so we just use
        # python's zlib, but we need to advance the pos value.
        zlib_text, n = neo_uncompress_loose(data[zpos:], hdr.zlib_text_usize)
        zpos += n

        zlib_data, n = neo_uncompress_loose(data[zpos:], hdr.zlib_data_usize)
        zpos += n

        zpos += hdr.zlib_relocations_sz

        uncompress = zlib_uncompress
    else:
        uncompress = neo_uncompress

    fixup_rsrc_data = None
    fixup_patch_data = b''
    if reversible:
        # Reversible provides us with patch bytes that fixup any missing
        # data.
        if rev_hdr.fixup_rsrc_csize:
            fixup_rsrc_data = uncompress(data[pos:pos+rev_hdr.fixup_rsrc_csize], rev_hdr.fixup_rsrc_count*4)
            pos += rev_hdr.fixup_rsrc_csize
        fixup_patch_data = uncompress(data[pos:pos+rev_hdr.fixup_patch_csize], rev_hdr.image_size)
        pos += rev_hdr.fixup_patch_csize

        # Should be the same as pos, but just in case
        if pos != zpos_start:
            raise Exception
        if zpos - zpos_start != rev_hdr.zlib_csize:
            raise Exception

    pos = zpos

    # Decompress the stored section data
    section_info = {}
    for info in hdr.sections:
        info.data = uncompress(data[pos:pos+info.csize], info.usize)
        pos += info.csize
        section_info[info.idx] = info

    reloc_data = b''
    if not reversible and hdr.reloc_csize:
        # Decompress the neolite formatted relocation data
        reloc_data = uncompress(data[pos:pos+hdr.reloc_csize], hdr.reloc_usize)
        pos += hdr.reloc_csize

    # Lets build up the new file
    new_data = bytearray(data[:pe.OPTIONAL_HEADER.SizeOfHeaders])
    new_sections = []
    raw_offset = raw_start

    sections_offset = pe.sections[0].get_file_offset()

    neolit_range = None
    neolit_offset = None
    reloc_section = None
    found_code = False
    found_data = False
    imports_data = None
    imports_raw_offset = None
    exports_offset = None
    exports_raw_offset = None
    rsrc_raw_offset = None

    if hdr.imports_offset:
        imports_offset = hdr.imports_offset
    else:
        imports_offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress

    rsrc_offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress

    if not reversible:
        # We'll need to generate these ourselves
        pe.OPTIONAL_HEADER.SizeOfCode = 0
        pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
        pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0

    # Scan and perform surgery on the sections
    for section_idx, section in enumerate(pe.sections):
        section_name = section.Name.rstrip(b'\0')

        if section_name == b'.neolit':
            neolit_range = range(section.VirtualAddress, section.VirtualAddress+section.SizeOfRawData)
            neolit_offset = section.VirtualAddress - section.PointerToRawData
            continue

        if section_name == b'.reloc':
            continue

        if section_idx == hdr.resource_section_idx:
            if section_idx not in section_info and not hdr.resource_offset:
                # Delete now unused resource section
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress = 0
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size = 0
                continue

        # Use this section for our output file
        section.set_file_offset(sections_offset + section.sizeof() * len(new_sections))
        new_sections.append(section)

        # Fixup this section name, neolite munged it
        if section_name == b'Oreloc' and not reversible:
            name = bytearray(section.Name)
            name[0:1] = b'.'
            section.Name = bytes(name)
            reloc_section = section

        # Get the uncompressed data from the source dll
        if section.PointerToRawData:
            sdata = section.get_data()
            if section_idx == hdr.resource_section_idx:
                # Neolite can re-use some of it's resources or overwrite as needed
                if len(sdata) < hdr.resource_offset:
                    sdata += bytes(hdr.resource_offset - len(sdata))
                elif len(sdata) > hdr.resource_offset:
                    sdata = sdata[:hdr.resource_offset]
                if not reversible:
                    sz = len(sdata)
                    pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size = (sz - sz % -4) + 4
        else:
            sdata = None

        # And now get the data that was compressed if we have it for this section
        info = section_info.get(section_idx, None)
        if info:
            if section_idx == hdr.resource_section_idx:
                # Resource data can get combined
                if sdata:
                    sdata += info.data
                else:
                    sdata = info.data
                if not reversible:
                    sz = len(sdata)
                    pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size = (sz - sz % -4) + 4
            else:
                sdata = info.data
            section.Characteristics = info.flags

        if sdata and len(sdata) > section.SizeOfRawData:
            section.SizeOfRawData = len(sdata)

        if not reversible:
            if section.SizeOfRawData:
                sz = section.SizeOfRawData
                sz -= sz % -pe.OPTIONAL_HEADER.FileAlignment
                section.SizeOfRawData = sz

            # We need to adjust header fields as appropriate ourselves
            misc = section.Misc + pe.OPTIONAL_HEADER.SectionAlignment - 1
            misc = pe.adjust_SectionAlignment(misc, pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment)
            if section.IMAGE_SCN_CNT_CODE:
                pe.OPTIONAL_HEADER.SizeOfCode += misc
                if not found_code:
                    pe.OPTIONAL_HEADER.BaseOfCode = section.VirtualAddress
                    found_code = True
            elif section.IMAGE_SCN_CNT_INITIALIZED_DATA:
                pe.OPTIONAL_HEADER.SizeOfInitializedData += misc
                if not found_data:
                    pe.OPTIONAL_HEADER.BaseOfData = section.VirtualAddress
                    found_data = True
            elif section.IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                pe.OPTIONAL_HEADER.SizeOfUninitializedData += misc

        if sdata is None:
            continue

        if reversible:
            if section_idx >= len(rev_hdr.sections):
                raise Exception(f'Offset of {section_name} not included')
            elif not sdata:
                raise Exception(f'Missing data for {section_name}')
            else:
                offset = rev_hdr.sections[section_idx]
        else:
            # Calculate new offsets for this section data
            if raw_offset > len(new_data):
                new_data += bytes(raw_offset - len(new_data))
            offset = raw_offset
            raw_offset += section.SizeOfRawData

        if offset > len(new_data):
            new_data += bytes(offset - len(new_data))
        new_data += sdata
        section.PointerToRawData = offset

        if imports_offset >= section.VirtualAddress and imports_offset < section.VirtualAddress + section.SizeOfRawData:
            # Located the section with the original imports data
            imports_data = sdata[imports_offset-section.VirtualAddress:]
            imports_raw_offset = imports_offset - section.VirtualAddress + section.PointerToRawData

        if rsrc_offset >= section.VirtualAddress and rsrc_offset < section.VirtualAddress + section.SizeOfRawData:
            # Located the rsrc section
            rsrc_raw_offset = rsrc_offset - section.VirtualAddress + section.PointerToRawData

        if section_name == b'.edata':
            # We assume we can use a section called '.edata' to store our exports
            exports_offset = section.VirtualAddress
            exports_raw_offset = section.PointerToRawData

    if not reversible:
        end = new_sections[-1].VirtualAddress + new_sections[-1].Misc_VirtualSize + pe.OPTIONAL_HEADER.SectionAlignment - 1
        end = pe.adjust_SectionAlignment(end, pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment)
        pe.OPTIONAL_HEADER.SizeOfImage = end

    if reversible:
        image_size = rev_hdr.image_size
        if hdr.image_size and image_size != hdr.image_size:
            raise Exception
    else:
        image_size = hdr.image_size
    
    if image_size:
        # Zero fill or trim
        if image_size < len(new_data):
            raise Exception(f'{image_size=:x} {len(new_data)=:x}')
        if image_size > len(new_data):
            new_data += bytes(image_size - len(new_data))

    if hdr_offset > file_end and pos < len(data):
        raise Exception('Data after and before neolite data, unhandled')
    elif hdr_offset > file_end:
        # Data at end of PE image
        extra_data_offset = file_end
        extra_data_size = hdr_offset - file_end
    elif pos < len(data):
        # Data at end of file
        extra_data_offset = pos
        extra_data_size = len(data) - pos
    else:
        extra_data_offset = 0
        extra_data_size = 0

    if hdr.extra_data_usize:
        # Neodatasim header
        extra_data_offset += 0x94
        extra_data_size -= 0x94
        if hdr.extra_data_csize:
            if hdr.extra_data_csize != extra_data_size:
                raise Exception
        elif hdr.extra_data_usize != extra_data_size:
            raise Exception

        if reversible:
            if rev_hdr.original_file_size - image_size != hdr.extra_data_usize:
                raise Exception

    # Copy data at end of file to end of file.
    if hdr.extra_data_csize:
        if hdr.use_zlib:
            udata = zlib.decompress(data[extra_data_offset:extra_data_offset+extra_data_size])
            if len(udata) != hdr.extra_data_usize:
                raise Exception
        else:
            udata = uncompress(data[extra_data_offset:extra_data_offset+extra_data_size], hdr.extra_data_usize)
        new_data += udata
    elif extra_data_size:
        new_data += data[extra_data_offset:extra_data_offset+extra_data_size]

    if imports_data is None:
        raise Exception('Could not find import data')

    # Find the size and end address of imports table
    imports_size = None
    imports_end = 0
    for n in range(0, len(imports_data), 20):
        if imports_data[n:n+20] == bytes(20):
            # Empty field indicates end, allowing us to count size
            imports_size = n+20
            imports_end = max(imports_end, n+20)
            break
        else:
            # Parse the imports table so we can determine where it all ends
            # in case we need to put the exports after the end of the imports.
            orig = int.from_bytes(imports_data[n:n+4], 'little')
            for o in range(orig-imports_offset, len(imports_data), 4):
                by_name = int.from_bytes(imports_data[o:o+4], 'little')
                if not by_name:
                    imports_end = max(imports_end, o+4)
                    break
                if by_name & 0x80000000 == 0:
                    end = imports_data.find(b'\0', by_name+2-imports_offset)
                    if end == -1:
                        raise Exception
                    imports_end = max(imports_end, end+1)
            name = int.from_bytes(imports_data[n+12:n+16], 'little')
            end = imports_data.find(b'\0', name-imports_offset)
            if end == -1:
                raise Exception(f'Could not find string end for name at {name:x}')
            imports_end = max(imports_end, end+1)

    if imports_size is None:
        raise Exception(f'Could not find imports at {imports_offset=:08x}')

    # Fixup imports table
    if hdr.imports_offset:
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = hdr.imports_offset
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = imports_size

    if not reversible:
        if exports_offset is None:
            # neolite doesn't tell us where the original imports table was. Our
            # first guess is the .edata section. If there is no .edata section
            # our next guess is to put the exports table at the end of the
            # imports table. If this fails too we could allocate a new .edata
            # section just so stuff could work.
            imports_end += hdr.imports_offset
            imports_end -= imports_end % -16

            exports_offset = imports_end
            exports_raw_offset = imports_end - hdr.imports_offset + imports_raw_offset

        # Fixup the export table, neolite moved it to it's own section, try and
        # move it back where it belongs. This involves doing relocations.
        start = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
        sz = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        if sz:
            section = pe.get_section_by_rva(start)
            offset = start - section.get_VirtualAddress_adj() + section.PointerToRawData
            export_data = bytearray(data[offset:offset+sz])
            if new_data[exports_raw_offset:exports_raw_offset+sz] != bytes(sz):
                raise Exception('Could not find free space for exports table')

            # Relocate addresses
            for i in (0xc, 0x1c, 0x20, 0x24):
                v = int.from_bytes(export_data[i:i+4], 'little')
                v += exports_offset - start
                export_data[i:i+4] = v.to_bytes(4, 'little')

            names = int.from_bytes(export_data[0x20:0x24], 'little') - exports_offset
            name_count = int.from_bytes(export_data[0x18:0x1c], 'little')
            for i in range(names, names+name_count*4, 4):
                v = int.from_bytes(export_data[i:i+4], 'little')
                v += exports_offset - start
                export_data[i:i+4] = v.to_bytes(4, 'little')

            new_data[exports_raw_offset:exports_raw_offset+sz] = export_data
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress = exports_offset

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
                    if len(curr_relocs) % 4:
                        curr_relocs += bytes(2)
                    relocs += struct.pack('<II', page * 4096, len(curr_relocs) + 8)
                    relocs += curr_relocs
                page = address // 4096
                curr_relocs = b''
            curr_relocs += struct.pack('<H', (address - page * 4096) | (3 << 12))

        if curr_relocs:
            if len(curr_relocs) % 4:
                curr_relocs += bytes(2)
            relocs += struct.pack('<II', page * 4096, len(curr_relocs) + 8)
            relocs += curr_relocs

        if len(relocs):
            if len(relocs) > reloc_section.SizeOfRawData:
                raise Exception(f'Reloc section ({reloc_section.SizeOfRawData}) too small to fit relocs ({len(relocs)})')

            roffset = reloc_section.PointerToRawData
            if new_data[roffset:roffset+len(relocs)] != bytes(len(relocs)):
                raise Exception('Existing data where we thought we should put the relocs')

            new_data[roffset:roffset+len(relocs)] = relocs

            pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress = reloc_section.VirtualAddress
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = len(relocs)

        else:
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress = 0
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = 0
            pe.FILE_HEADER.Characteristics |= 0x0001 # IMAGE_FILE_RELOCS_STRIPPED

    # Fixup rsrc. neolite can shuffle entries so that certain entries at the
    # start of rsrc remain uncompressed and accessible. Normally there's no way
    # to know what the original order was, but with the reversible option a
    # fixup table is provided so we can shuffle them back.
    if fixup_rsrc_data:
        offsets = [0]
        entries = set()
        while offsets:
            offset = offsets.pop() + rsrc_raw_offset
            _, _, _, _, name_cnt, id_cnt = struct.unpack_from('<IIHHHH', new_data, offset)
            offset += 16# + 8 * name_cnt
            for _, o in struct.iter_unpack('<II', new_data[offset:offset+8*(id_cnt+name_cnt)]):
                if o & 0x80000000:
                    offsets.append(o & 0x7fffffff)
                else:
                    entries.add(o + rsrc_raw_offset)
        if len(entries) != rev_hdr.fixup_rsrc_count:
            raise Exception(f'{len(entries)=} {rev_hdr.fixup_rsrc_count=}')

        fixups = struct.unpack(f'<{rev_hdr.fixup_rsrc_count}I', fixup_rsrc_data)
        copies = []
        for fixup, entry in zip(fixups, sorted(entries)):
            orig_rva, sz, page, res = struct.unpack_from('<IIII', new_data, entry)
            adj_sz = (sz - sz % -4) + 4
            new_rva = (orig_rva + fixup) & 0xffffffff
            orig_rva_phys = orig_rva - rsrc_offset + rsrc_raw_offset
            new_rva_phys = new_rva - rsrc_offset + rsrc_raw_offset
            new_data[entry:entry+4] = new_rva.to_bytes(4, 'little')
            copies.append((new_rva_phys, new_data[orig_rva_phys:orig_rva_phys+sz] + bytes(adj_sz - sz)))

        # Shuffle the actual data back into place.
        for phys, sdata in copies:
            new_data[phys:phys+len(sdata)] = sdata

    # Fixup IAT
    if hdr.iat_offset:
        if not reversible:
            # The fixup data handles this for us, if we don't have it we must
            # undo it outselves.
            for n, o in enumerate(struct.unpack_from(f'<{hdr.iat_sz//4}I', new_data, hdr.iat_offset)):
                if o & 0x80000000 == 0:
                    # Check if field is in neolite section
                    if neolit_range and o in neolit_range:
                        # Copy the ordinal
                        o -= neolit_offset
                        new_data[hdr.iat_offset+n*4:hdr.iat_offset+n*4+4] = data[o:o+4]
            hdr.iat_sz += 4
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress = hdr.iat_offset
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].Size = hdr.iat_sz

    # Fixup TLS
    if hdr.tls_data:
        # Didn't need this so didn't code it. It shouldn't be difficult. You
        # can do this, I believe in you.
        raise Exception('tls data fixup currently not handled')

    # Remove unused sections
    for section in pe.sections:
        if section not in new_sections:
            new_data[section.get_file_offset():section.get_file_offset()+section.sizeof()] = bytes(section.sizeof())
            pe.__structures__.remove(section)
    pe.FILE_HEADER.NumberOfSections = len(new_sections)
    pe.sections = new_sections

    # Don't try to write out the stuff *in* sections, just the header thanks
    pe.__structures__ = filter(lambda s: s.get_file_offset() < pe.OPTIONAL_HEADER.SizeOfHeaders, pe.__structures__)

    # apply changes
    pe.__data__ = bytes(new_data)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = hdr.orig_entry

    if reversible:
        pe.FILE_HEADER.Characteristics = rev_hdr.flags

    # Have pe write out the changes to the pe file headers
    new_data[:pe.OPTIONAL_HEADER.SizeOfHeaders] = bytearray(pe.write()[:pe.OPTIONAL_HEADER.SizeOfHeaders])

    # Apply fixup data provided if reversible
    for n, f in enumerate(fixup_patch_data):
        new_data[n] = (new_data[n] + f) & 0xff

    # Generate new checksum.
    if not reversible:
        pe = pefile.PE(data=new_data)
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        new_data = pe.write()

    return bytes(new_data)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: neolite_unpack.py <input dll> [<output dll>]')
        sys.exit(1)

    data = open(sys.argv[1], 'rb').read()
    if not is_neolite(data):
        print(f'Not a Neolite executable: {sys.argv[1]}')
        sys.exit(1)

    if len(sys.argv) == 3:
        new_data = fixup(data)
        open(sys.argv[2], 'wb').write(new_data)
        print(f'Unpacked {len(new_data)} bytes, {int(100*len(data)/len(new_data))}%: {sys.argv[1]}->{sys.argv[2]}')
    else:
        print_info(data)
        new_data = fixup(data)
        print(f'Neolite packed executable {len(new_data)} bytes, {int(100*len(data)/len(new_data))}%: {sys.argv[1]}')


