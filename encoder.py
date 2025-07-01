#!/usr/bin/env python3
import argparse
import base64
import sys
import html
import gzip
import urllib.parse
import re
import hashlib
import codecs
import json
import binascii

def read_input(file):
    if file:
        return open(file, 'r', encoding='utf-8').read()
    elif not sys.stdin.isatty():
        return sys.stdin.read()
    else:
        sys.exit("No input. Pipe text or use -f <file>.")

# Base encoders/decoders
def urlencode_ascii(s): return ''.join(f'%{ord(c):02X}' for c in s)
def xml_encode(s): return ''.join(f'&#x{ord(c):X}' for c in s)
def encode_base85(s): return base64.a85encode(s.encode()).decode()
def encode_base64(s): return base64.b64encode(s.encode()).decode()
def encode_b64_url(s): return base64.urlsafe_b64encode(s.encode()).decode()
def encode_ascii_hex(s): return ''.join(f"{ord(c):02X}" for c in s)
def encode_hex(s): return s.encode().hex()
def encode_octal(s): return ' '.join(oct(ord(c))[2:] for c in s)
def encode_binary(s): return ' '.join(bin(ord(c))[2:].zfill(8) for c in s)
def encode_gzip(s): return base64.b64encode(gzip.compress(s.encode())).decode()
def rot13(s): return s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                             "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
def caesar(s, shift): return ''.join(
    chr((ord(c) - base + shift) % 26 + base) if c.isalpha() else c
    for c in s
    for base in (65, 97) if c.isupper() or c.islower()
) or s
def xor_cipher(s, key):
    return ''.join(chr(ord(c) ^ key) for c in s)
def hash_md5(s): return hashlib.md5(s.encode()).hexdigest()
def hash_sha1(s): return hashlib.sha1(s.encode()).hexdigest()
def hash_sha256(s): return hashlib.sha256(s.encode()).hexdigest()

# Advanced Web App Pentesting Obfuscation Methods

# Double/Triple URL Encoding - Critical for WAF bypassing
def double_urlencode(s):
    # First encode all characters including letters
    first_encode = ''.join(f'%{ord(c):02X}' for c in s)
    # Then encode again
    return urllib.parse.quote(first_encode, safe='')

def triple_urlencode(s):
    # First encode all characters including letters
    first_encode = ''.join(f'%{ord(c):02X}' for c in s)
    # Then encode twice more
    second_encode = urllib.parse.quote(first_encode, safe='')
    return urllib.parse.quote(second_encode, safe='')

def decode_double_url(s):
    return urllib.parse.unquote(urllib.parse.unquote(s))

def decode_triple_url(s):
    return urllib.parse.unquote(urllib.parse.unquote(urllib.parse.unquote(s)))

def urlencode_all_chars(s):
    """URL encode ALL characters including letters and digits"""
    return ''.join(f'%{ord(c):02X}' for c in s)

# Unicode Encoding Variants
def unicode_escape(s):
    return ''.join(f'\\u{ord(c):04x}' for c in s)

def unicode_escape_mixed(s):
    # Mix \\u and \\x formats for evasion
    result = ''
    for i, c in enumerate(s):
        if i % 2 == 0 and ord(c) < 256:
            result += f'\\x{ord(c):02x}'
        else:
            result += f'\\u{ord(c):04x}'
    return result

def unicode_overlong_utf8(s):
    # Create overlong UTF-8 sequences for bypass
    result = ''
    for c in s:
        if ord(c) < 128:
            # Overlong 2-byte sequence
            result += f'%C{((ord(c) >> 6) | 0xC0):02X}%{((ord(c) & 0x3F) | 0x80):02X}'
        else:
            result += urllib.parse.quote(c)
    return result

def decode_unicode_escape(s):
    return codecs.decode(s, 'unicode_escape')

# HTML Entity Variations
def html_named_entities(s):
    # Use named entities where possible
    entity_map = {
        '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;',
        ' ': '&nbsp;', '©': '&copy;', '®': '&reg;', '™': '&trade;'
    }
    return ''.join(entity_map.get(c, f'&#{ord(c)};') for c in s)

def html_hex_entities(s):
    return ''.join(f'&#x{ord(c):x};' for c in s)

def html_decimal_entities(s):
    return ''.join(f'&#{ord(c)};' for c in s)

def html_hex_entities_leading_zeros(s):
    """HTML hex encoding with leading zeros to bypass WAFs"""
    import random
    result = ''
    for c in s:
        # Add 2-8 leading zeros randomly
        zeros = '0' * random.randint(2, 8)
        result += f'&#x{zeros}{ord(c):x};'
    return result

def html_decimal_entities_leading_zeros(s):
    """HTML decimal encoding with leading zeros to bypass WAFs"""
    import random
    result = ''
    for c in s:
        # Add 2-8 leading zeros randomly
        zeros = '0' * random.randint(2, 8)
        result += f'&#{zeros}{ord(c)};'
    return result

def xml_hex_entities_leading_zeros(s):
    """XML hex encoding with leading zeros"""
    import random
    result = ''
    for c in s:
        zeros = '0' * random.randint(3, 10)
        result += f'&#x{zeros}{ord(c):x};'
    return result

def xml_decimal_entities_leading_zeros(s):
    """XML decimal encoding with leading zeros"""
    import random
    result = ''
    for c in s:
        zeros = '0' * random.randint(3, 10)
        result += f'&#{zeros}{ord(c)};'
    return result

# Advanced Unicode Escaping with Leading Zeros
def unicode_escape_leading_zeros(s):
    """Unicode escape with leading zeros \\u{000000XX}"""
    import random
    result = ''
    for c in s:
        # Add 2-8 leading zeros
        zeros = '0' * random.randint(2, 8)
        result += f'\\u{{{zeros}{ord(c):x}}}'
    return result

def unicode_escape_traditional_leading_zeros(s):
    """Traditional unicode escape \\u0000XX with leading zeros"""
    import random
    result = ''
    for c in s:
        # Ensure we have 4+ digits with leading zeros
        zeros = '0' * random.randint(4, 8)
        hex_val = f'{ord(c):x}'
        if len(zeros + hex_val) > 8:
            zeros = zeros[:8-len(hex_val)]
        result += f'\\u{zeros}{hex_val}'
    return result

def js_unicode_escape_leading_zeros(s):
    """JavaScript unicode escape with excessive leading zeros"""
    import random
    result = ''
    for c in s:
        # ES6 style with leading zeros
        zeros = '0' * random.randint(4, 12)
        result += f'\\u{{{zeros}{ord(c):x}}}'
    return result

# Enhanced Hex Escaping
def hex_escape_leading_zeros(s):
    """Hex escape with leading zeros \\x00XX"""
    import random
    result = ''
    for c in s:
        if ord(c) < 256:
            zeros = '0' * random.randint(1, 4)
            result += f'\\x{zeros}{ord(c):02x}'
        else:
            result += c
    return result

# Multiple Encoding Combinations
def html_unicode_double_encode(s):
    """HTML encode then Unicode escape - multiple layer obfuscation"""
    # First HTML encode
    html_encoded = ''.join(f'&#{ord(c)};' for c in s)
    # Then Unicode escape the result
    return ''.join(f'\\u{ord(c):04x}' for c in html_encoded)

def unicode_html_double_encode(s):
    """Unicode escape then HTML encode"""
    # First Unicode escape
    unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in s)
    # Then HTML encode the result
    return ''.join(f'&#{ord(c)};' for c in unicode_encoded)

def url_html_double_encode(s):
    """URL encode then HTML encode"""
    # First URL encode everything
    url_encoded = ''.join(f'%{ord(c):02X}' for c in s)
    # Then HTML encode the result
    return ''.join(f'&#{ord(c)};' for c in url_encoded)

def html_url_double_encode(s):
    """HTML encode then URL encode"""
    # First HTML encode
    html_encoded = ''.join(f'&#{ord(c)};' for c in s)
    # Then URL encode the result
    return ''.join(f'%{ord(c):02X}' for c in html_encoded)

def triple_encode_url_html_unicode(s):
    """Triple encoding: URL → HTML → Unicode"""
    # URL encode
    url_encoded = ''.join(f'%{ord(c):02X}' for c in s)
    # HTML encode
    html_encoded = ''.join(f'&#{ord(c)};' for c in url_encoded)
    # Unicode escape
    return ''.join(f'\\u{ord(c):04x}' for c in html_encoded)

# Advanced SQL Obfuscation
def sql_char_hex_mixed(s):
    """Mix CHAR() with hex notation"""
    import random
    result = []
    for c in s:
        if random.choice([True, False]):
            result.append(f'CHAR({ord(c)})')
        else:
            result.append(f'CHAR(0x{ord(c):02X})')
    return '+'.join(result)

def sql_unhex_encode(s):
    """SQL UNHEX() function encoding"""
    hex_string = ''.join(f'{ord(c):02X}' for c in s)
    return f'UNHEX("{hex_string}")'

def sql_hex_literal(s):
    """SQL hex literal 0xXXXXXX"""
    return '0x' + ''.join(f'{ord(c):02X}' for c in s)

def sql_binary_encode(s):
    """SQL binary literal encoding"""
    binary_string = ''.join(f'{ord(c):08b}' for c in s)
    return f'BINARY({binary_string})'

def sql_ascii_encode(s):
    """SQL ASCII() and CHAR() combination"""
    return '+'.join(f'CHAR(ASCII("{c}"))' for c in s)

# JavaScript Context Specific
def js_string_fromcharcode_split(s):
    """JavaScript String.fromCharCode() with array splitting"""
    char_codes = [str(ord(c)) for c in s]
    # Split into chunks to avoid detection
    chunks = [char_codes[i:i+3] for i in range(0, len(char_codes), 3)]
    parts = []
    for chunk in chunks:
        parts.append(f'String.fromCharCode({",".join(chunk)})')
    return '+'.join(parts)

def js_eval_fromcharcode(s):
    """JavaScript eval with fromCharCode obfuscation"""
    char_codes = ','.join(str(ord(c)) for c in s)
    return f'eval(String.fromCharCode({char_codes}))'

def js_unescape_encode(s):
    """JavaScript unescape() with percent encoding"""
    encoded = ''.join(f'%{ord(c):02X}' for c in s)
    return f'unescape("{encoded}")'

# PHP Context Specific
def php_chr_hex_mixed(s):
    """PHP chr() with mixed decimal and hex"""
    import random
    result = []
    for c in s:
        if random.choice([True, False]):
            result.append(f'chr({ord(c)})')
        else:
            result.append(f'chr(0x{ord(c):02X})')
    return '.'.join(result)

def php_pack_encode(s):
    """PHP pack() function encoding"""
    format_chars = 'C' * len(s)  # Unsigned char format
    char_codes = ','.join(str(ord(c)) for c in s)
    return f'pack("{format_chars}",{char_codes})'

def php_hex2bin_encode(s):
    """PHP hex2bin() encoding"""
    hex_string = ''.join(f'{ord(c):02x}' for c in s)
    return f'hex2bin("{hex_string}")'

# PowerShell Specific
def powershell_char_array(s):
    """PowerShell character array conversion"""
    char_codes = ','.join(str(ord(c)) for c in s)
    return f'[char[]]({char_codes})-join""'

def powershell_format_operator(s):
    """PowerShell format operator obfuscation"""
    format_string = '{' + '}{'.join(str(i) for i in range(len(s))) + '}'
    args = ','.join(f'[char]{ord(c)}' for c in s)
    return f'"{format_string}"-f{args}'

# Linux/Bash Specific  
def bash_dollar_escape(s):
    """Bash $'\\xXX' escaping"""
    return "$'" + ''.join(f'\\x{ord(c):02x}' for c in s) + "'"

def bash_printf_escape(s):
    """Bash printf escaping"""
    format_str = ''.join('\\x%02x' for _ in s)
    char_codes = ' '.join(str(ord(c)) for c in s)
    return f'printf "{format_str}" {char_codes}'

# Advanced XML Techniques
def xml_cdata_escape(s):
    """XML CDATA with nested payload"""
    return f'<![CDATA[{s}]]>'

def xml_processing_instruction(s):
    """XML processing instruction obfuscation"""
    encoded = ''.join(f'&#x{ord(c):x};' for c in s)
    return f'<?xml version="1.0"?>{encoded}'

# Advanced Base64 Variations
def base64_chunked_encode(s):
    """Base64 with chunking to avoid pattern detection"""
    import base64
    encoded = base64.b64encode(s.encode()).decode()
    # Split into chunks of 4-8 characters
    chunks = [encoded[i:i+6] for i in range(0, len(encoded), 6)]
    return '+'.join(f'"{chunk}"' for chunk in chunks)

def base64_with_decode_function(s):
    """Base64 with decode function call"""
    import base64
    encoded = base64.b64encode(s.encode()).decode()
    return f'atob("{encoded}")'  # JavaScript atob function

# Case Obfuscation Advanced
def case_unicode_mixed(s):
    """Mix case with Unicode variations"""
    result = ''
    for i, c in enumerate(s):
        if c.isalpha():
            if i % 3 == 0:
                result += c.upper()
            elif i % 3 == 1:
                result += c.lower()
            else:
                # Use mathematical Unicode
                if 'A' <= c.upper() <= 'Z':
                    # Mathematical Bold
                    if c.isupper():
                        result += chr(0x1D400 + (ord(c) - ord('A')))
                    else:
                        result += chr(0x1D41A + (ord(c) - ord('a')))
                else:
                    result += c
        else:
            result += c
    return result

# JavaScript/JSON Escaping
def js_unicode_escape(s):
    return ''.join(f'\\u{ord(c):04x}' for c in s)

def js_hex_escape(s):
    return ''.join(f'\\x{ord(c):02x}' if ord(c) < 256 else f'\\u{ord(c):04x}' for c in s)

def json_escape(s):
    return json.dumps(s)[1:-1]  # Remove surrounding quotes

# Base32 and Base58 (common in cryptocurrency/blockchain contexts)
def encode_base32(s):
    return base64.b32encode(s.encode()).decode()

def decode_base32(s):
    return base64.b32decode(s.encode()).decode()

def encode_base58(s):
    # Bitcoin-style base58
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(s.encode(), 'big')
    if num == 0:
        return alphabet[0]
    result = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        result = alphabet[remainder] + result
    return result

def decode_base58(s):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in s:
        num = num * 58 + alphabet.index(char)
    return num.to_bytes((num.bit_length() + 7) // 8, 'big').decode()

# LDAP Escaping (for LDAP injection testing)
def ldap_escape(s):
    escape_map = {
        '\\': '\\5c', '*': '\\2a', '(': '\\28', ')': '\\29',
        '\x00': '\\00', '/': '\\2f'
    }
    return ''.join(escape_map.get(c, c) for c in s)

# CSS Escaping
def css_escape(s):
    return ''.join(f'\\{ord(c):x} ' if not c.isalnum() else c for c in s)

# SQL Escaping variations
def sql_char_encoding(s):
    # Convert to CHAR() functions
    return 'CHAR(' + ','.join(str(ord(c)) for c in s) + ')'

def sql_hex_encoding(s):
    return '0x' + s.encode().hex()

# PowerShell Escaping
def powershell_escape(s):
    escape_chars = "'^\"$`(){};,|&<>@#"
    return ''.join(f'`{c}' if c in escape_chars else c for c in s)

# Mixed Case Obfuscation
def mixed_case(s):
    return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

# UTF-7 Encoding (often bypasses filters)
def utf7_encode(s):
    return s.encode('utf-7').decode('ascii')

def utf7_decode(s):
    return s.encode('ascii').decode('utf-7')

# UTF-16 Encoding
def utf16_encode(s):
    return s.encode('utf-16').hex()

def utf16_decode(s):
    return bytes.fromhex(s).decode('utf-16')

# Morse Code (surprisingly effective sometimes)
def morse_encode(s):
    morse_map = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    return ' '.join(morse_map.get(c.upper(), c) for c in s)

# Atbash Cipher (Hebrew cipher - A=Z, B=Y, etc.)
def atbash_cipher(s):
    return ''.join(
        chr(25 - (ord(c) - ord('A')) + ord('A')) if c.isupper() else
        chr(25 - (ord(c) - ord('a')) + ord('a')) if c.islower() else c
        for c in s
    )

# Vigenere Cipher
def vigenere_encode(s, key):
    key = key.upper()
    result = ''
    key_index = 0
    for c in s:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(c) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += c
    return result

def vigenere_decode(s, key):
    key = key.upper()
    result = ''
    key_index = 0
    for c in s:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(c) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += c
    return result

# PHP Serialization
def php_serialize(s):
    return f's:{len(s)}:"{s}";'

# Python Pickle (hex encoded for safety)
def python_pickle_hex(s):
    import pickle
    return pickle.dumps(s).hex()

# Backslash Escaping
def backslash_escape(s):
    return ''.join(f'\\{c}' for c in s)

# Windows-1252 Encoding
def windows1252_encode(s):
    return s.encode('windows-1252', errors='replace').hex()

def windows1252_decode(s):
    return bytes.fromhex(s).decode('windows-1252', errors='replace')

# Custom Substitution Cipher (ROT variants)
def rot47(s):
    return ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)

# Mathematical Unicode Obfuscation - "Funny Unicode"
def math_unicode_encode(s):
    """Convert normal letters to mathematical Unicode equivalents"""
    result = ''
    for c in s:
        if 'A' <= c <= 'Z':
            # Mathematical Bold Capital Letters (U+1D400-U+1D419)
            result += chr(0x1D400 + (ord(c) - ord('A')))
        elif 'a' <= c <= 'z':
            # Mathematical Bold Small Letters (U+1D41A-U+1D433)
            result += chr(0x1D41A + (ord(c) - ord('a')))
        elif '0' <= c <= '9':
            # Mathematical Bold Digits (U+1D7CE-U+1D7D7)
            result += chr(0x1D7CE + (ord(c) - ord('0')))
        else:
            result += c
    return result

def math_unicode_monospace_encode(s):
    """Convert to mathematical monospace Unicode (even sneakier)"""
    result = ''
    for c in s:
        if 'A' <= c <= 'Z':
            # Mathematical Monospace Capital Letters (U+1D670-U+1D689)
            result += chr(0x1D670 + (ord(c) - ord('A')))
        elif 'a' <= c <= 'z':
            # Mathematical Monospace Small Letters (U+1D68A-U+1D6A3)
            result += chr(0x1D68A + (ord(c) - ord('a')))
        elif '0' <= c <= '9':
            # Mathematical Monospace Digits (U+1D7F6-U+1D7FF)
            result += chr(0x1D7F6 + (ord(c) - ord('0')))
        else:
            result += c
    return result

def math_unicode_decode(s):
    """Decode mathematical Unicode back to normal characters"""
    result = ''
    for c in s:
        code = ord(c)
        if 0x1D400 <= code <= 0x1D419:  # Bold capitals
            result += chr(ord('A') + (code - 0x1D400))
        elif 0x1D41A <= code <= 0x1D433:  # Bold lowercase
            result += chr(ord('a') + (code - 0x1D41A))
        elif 0x1D7CE <= code <= 0x1D7D7:  # Bold digits
            result += chr(ord('0') + (code - 0x1D7CE))
        elif 0x1D670 <= code <= 0x1D689:  # Monospace capitals
            result += chr(ord('A') + (code - 0x1D670))
        elif 0x1D68A <= code <= 0x1D6A3:  # Monospace lowercase
            result += chr(ord('a') + (code - 0x1D68A))
        elif 0x1D7F6 <= code <= 0x1D7FF:  # Monospace digits
            result += chr(ord('0') + (code - 0x1D7F6))
        else:
            result += c
    return result

# Full-width Unicode (another sneaky technique)
def fullwidth_encode(s):
    """Convert to full-width Unicode characters"""
    result = ''
    for c in s:
        if ' ' <= c <= '~':  # Printable ASCII
            if c == ' ':
                result += '\u3000'  # Ideographic space
            else:
                # Full-width characters (U+FF01-U+FF5E)
                result += chr(0xFF00 + ord(c) - 0x20)
        else:
            result += c
    return result

def fullwidth_decode(s):
    """Decode full-width Unicode back to normal ASCII"""
    result = ''
    for c in s:
        code = ord(c)
        if c == '\u3000':  # Ideographic space
            result += ' '
        elif 0xFF01 <= code <= 0xFF5E:  # Full-width range
            result += chr(0x20 + (code - 0xFF00))
        else:
            result += c
    return result

# Invisible Unicode characters (zero-width)
def invisible_unicode_encode(s):
    """Insert invisible Unicode characters for steganography"""
    invisible_chars = [
        '\u200B',  # Zero Width Space
        '\u200C',  # Zero Width Non-Joiner
        '\u200D',  # Zero Width Joiner
        '\u2060',  # Word Joiner
        '\uFEFF',  # Zero Width No-Break Space
    ]
    result = ''
    for i, c in enumerate(s):
        result += c
        if i < len(s) - 1:  # Don't add at the end
            result += invisible_chars[i % len(invisible_chars)]
    return result

def invisible_unicode_decode(s):
    """Remove invisible Unicode characters"""
    invisible_chars = ['\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF']
    result = s
    for char in invisible_chars:
        result = result.replace(char, '')
    return result

# Funny Unicode chr() obfuscation - Ultimate Python bypass technique
def funny_unicode_chr_encode(s):
    """Convert string to mathematical Unicode chr() construction calls"""
    # Mathematical Unicode versions of chr, exec, eval
    math_chr = '𝚌𝚑𝚛'  # U+1D42C, U+1D421, U+1D42B
    math_exec = '𝚎𝚡𝚎𝚌'  # U+1D42E, U+1D431, U+1D42E, U+1D42C
    
    # Convert each character to 𝚌𝚑𝚛(ord) + 
    chr_calls = []
    for c in s:
        chr_calls.append(f'{math_chr}({ord(c)})')
    
    # Join with ' + ' and wrap in 𝚎𝚡𝚎𝚌()
    result = ' + '.join(chr_calls)
    return f'{math_exec}({result})'

def funny_unicode_eval_encode(s):
    """Convert string to mathematical Unicode eval() construction calls"""
    math_chr = '𝚌𝚑𝚛'
    math_eval = '𝚎𝚟𝚊𝚕'  # U+1D42E, U+1D42F, U+1D42A, U+1D425
    
    chr_calls = []
    for c in s:
        chr_calls.append(f'{math_chr}({ord(c)})')
    
    result = ' + '.join(chr_calls)
    return f'{math_eval}({result})'

def funny_unicode_simple_encode(s):
    """Simple mathematical Unicode chr() construction without exec wrapper"""
    math_chr = '𝚌𝚑𝚛'
    
    chr_calls = []
    for c in s:
        chr_calls.append(f'{math_chr}({ord(c)})')
    
    return ' + '.join(chr_calls)

# Python-specific obfuscation variants
def python_unicode_import_encode(s):
    """Convert to __import__ with mathematical Unicode chr()"""
    math_chr = '𝚌𝚑𝚛'
    math_import = '__𝚒𝚖𝚙𝚘𝚛𝚝__'  # Mix regular __ with math Unicode
    
    chr_calls = []
    for c in s:
        chr_calls.append(f'{math_chr}({ord(c)})')
    
    module_construction = ' + '.join(chr_calls)
    return f'{math_import}({module_construction})'

def python_unicode_getattr_encode(s, obj="__builtins__"):
    """Convert to getattr() with mathematical Unicode chr()"""
    math_chr = '𝚌𝚑𝚛'
    math_getattr = '𝚐𝚎𝚝𝚊𝚝𝚝𝚛'  # Mathematical Unicode getattr
    
    chr_calls = []
    for c in s:
        chr_calls.append(f'{math_chr}({ord(c)})')
    
    attr_construction = ' + '.join(chr_calls)
    return f'{math_getattr}({obj}, {attr_construction})'

# Alternative mathematical Unicode sets
def funny_unicode_italic_encode(s):
    """Use mathematical italic Unicode chr()"""
    math_chr = '𝑐ℎ𝑟'  # U+1D450, U+210E, U+1D45F (Mathematical Italic)
    math_exec = '𝑒𝑥𝑒𝑐'  # U+1D452, U+1D465, U+1D452, U+1D450
    
    chr_calls = []
    for c in s:
        chr_calls.append(f'{math_chr}({ord(c)})')
    
    result = ' + '.join(chr_calls)
    return f'{math_exec}({result})'

# Flexible Funny Unicode - Convert ANY function to mathematical Unicode
def funny_unicode_any_function(s, function_name="exec"):
    """Convert any function name to mathematical Unicode with chr() construction"""
    
    # Mathematical Unicode character mappings (Monospace)
    math_chars = {
        'a': '𝚊', 'b': '𝚋', 'c': '𝚌', 'd': '𝚍', 'e': '𝚎', 'f': '𝚏', 'g': '𝚐', 'h': '𝚑',
        'i': '𝚒', 'j': '𝚓', 'k': '𝚔', 'l': '𝚕', 'm': '𝚖', 'n': '𝚗', 'o': '𝚘', 'p': '𝚙',
        'q': '𝚚', 'r': '𝚛', 's': '𝚜', 't': '𝚝', 'u': '𝚞', 'v': '𝚟', 'w': '𝚠', 'x': '𝚡',
        'y': '𝚢', 'z': '𝚣', '_': '_'  # Keep underscore as is
    }
    
    # Convert function name to mathematical Unicode
    math_function = ''.join(math_chars.get(c.lower(), c) for c in function_name)
    math_chr = '𝚌𝚑𝚛'
    
    # Convert string to chr() calls
    chr_calls = []
    for c in s:
        chr_calls.append(f'{math_chr}({ord(c)})')
    
    result = ' + '.join(chr_calls)
    return f'{math_function}({result})'

# Case Confusion WAF Bypasses
def case_alternating_encode(s):
    """WAF Bypass: Alternate between upper/lower case"""
    return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

def case_random_encode(s):
    """WAF Bypass: Random case mixing"""
    import random
    return ''.join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in s)

def case_vowel_upper_encode(s):
    """WAF Bypass: Uppercase vowels only"""
    vowels = 'aeiouAEIOU'
    return ''.join(c.upper() if c in vowels else c.lower() for c in s)

def case_consonant_upper_encode(s):
    """WAF Bypass: Uppercase consonants only"""
    vowels = 'aeiouAEIOU'
    return ''.join(c.upper() if c.isalpha() and c not in vowels else c.lower() for c in s)

# Unicode Compression Techniques
def unicode_zalgo_encode(s):
    """WAF Bypass: Add zalgo/combining marks to confuse parsers"""
    zalgo_marks = [
        '\u0300', '\u0301', '\u0302', '\u0303', '\u0304', '\u0305', '\u0306', '\u0307',
        '\u0308', '\u0309', '\u030A', '\u030B', '\u030C', '\u030D', '\u030E', '\u030F',
        '\u0310', '\u0311', '\u0312', '\u0313', '\u0314', '\u0315', '\u0316', '\u0317'
    ]
    import random
    result = ''
    for c in s:
        result += c
        if c.isalpha():  # Add zalgo to letters
            result += random.choice(zalgo_marks)
    return result

# Advanced Zalgo Variants for Fuzzing
def unicode_zalgo_crazy_encode(s, craziness=3, above=True, below=True, overlay=True):
    """Advanced zalgo with configurable craziness and mark types"""
    
    # Combining marks above (U+0300-U+036F)
    zalgo_above = [
        '\u0300', '\u0301', '\u0302', '\u0303', '\u0304', '\u0305', '\u0306', '\u0307',
        '\u0308', '\u0309', '\u030A', '\u030B', '\u030C', '\u030D', '\u030E', '\u030F',
        '\u0310', '\u0311', '\u0312', '\u0313', '\u0314', '\u0315', '\u0316', '\u0317',
        '\u0318', '\u0319', '\u031A', '\u031B', '\u031C', '\u031D', '\u031E', '\u031F',
        '\u0320', '\u0321', '\u0322', '\u0323', '\u0324', '\u0325', '\u0326', '\u0327'
    ]
    
    # Combining marks below
    zalgo_below = [
        '\u0316', '\u0317', '\u0318', '\u0319', '\u031C', '\u031D', '\u031E', '\u031F',
        '\u0320', '\u0321', '\u0322', '\u0323', '\u0324', '\u0325', '\u0326', '\u0327',
        '\u0328', '\u0329', '\u032A', '\u032B', '\u032C', '\u032D', '\u032E', '\u032F',
        '\u0330', '\u0331', '\u0332', '\u0333', '\u0334', '\u0335', '\u0336', '\u0337',
        '\u0338', '\u0339', '\u033A', '\u033B', '\u033C', '\u033D', '\u033E', '\u033F'
    ]
    
    # Overlay combining marks
    zalgo_overlay = [
        '\u0334', '\u0335', '\u0336', '\u0337', '\u0338', '\u0339', '\u033A', '\u033B',
        '\u033C', '\u033D', '\u033E', '\u033F', '\u0340', '\u0341', '\u0342', '\u0343',
        '\u0344', '\u0345', '\u0346', '\u0347', '\u0348', '\u0349', '\u034A', '\u034B',
        '\u034C', '\u034D', '\u034E', '\u034F', '\u0350', '\u0351', '\u0352', '\u0353'
    ]
    
    import random
    result = ''
    
    for c in s:
        result += c
        if c.isalpha() or c.isdigit():  # Add zalgo to alphanumeric
            marks_to_add = random.randint(1, craziness)
            
            for _ in range(marks_to_add):
                mark_type = random.choice(['above', 'below', 'overlay'])
                
                if mark_type == 'above' and above and zalgo_above:
                    result += random.choice(zalgo_above)
                elif mark_type == 'below' and below and zalgo_below:
                    result += random.choice(zalgo_below)
                elif mark_type == 'overlay' and overlay and zalgo_overlay:
                    result += random.choice(zalgo_overlay)
    
    return result

def unicode_confusables_encode(s):
    """WAF Bypass: Use Unicode confusable characters"""
    # Extended confusables beyond basic homographs
    confusables = {
        'a': ['а', 'ａ', 'α', 'а'], 'e': ['е', 'ｅ', 'ε', 'е'], 'o': ['о', 'ｏ', 'ο', 'о'],
        'p': ['р', 'ｐ', 'ρ', 'р'], 'c': ['с', 'ｃ', 'ϲ', 'с'], 'x': ['х', 'ｘ', 'χ', 'х'],
        'y': ['у', 'ｙ', 'γ', 'у'], 'i': ['і', 'ｉ', 'ι', 'і'], 'j': ['ј', 'ｊ', 'ϳ', 'ј'],
        'A': ['А', 'Ａ', 'Α', 'А'], 'B': ['В', 'Ｂ', 'Β', 'В'], 'C': ['С', 'Ｃ', 'Ϲ', 'С'],
        'E': ['Е', 'Ｅ', 'Ε', 'Е'], 'H': ['Н', 'Ｈ', 'Η', 'Н'], 'I': ['І', 'Ｉ', 'Ι', 'І'],
        'J': ['Ј', 'Ｊ', 'Ϳ', 'Ј'], 'K': ['К', 'Ｋ', 'Κ', 'К'], 'M': ['М', 'Ｍ', 'Μ', 'М'],
        'N': ['Ν', 'Ｎ', 'Ν', 'Ν'], 'O': ['О', 'Ｏ', 'Ο', 'О'], 'P': ['Р', 'Ｐ', 'Ρ', 'Р'],
        'S': ['Ѕ', 'Ｓ', 'Σ', 'Ѕ'], 'T': ['Т', 'Ｔ', 'Τ', 'Т'], 'X': ['Х', 'Ｘ', 'Χ', 'Х'],
        'Y': ['У', 'Ｙ', 'Υ', 'У'], 'Z': ['Ζ', 'Ｚ', 'Ζ', 'Ζ']
    }
    
    import random
    result = ''
    for c in s:
        if c in confusables:
            result += random.choice(confusables[c])
        else:
            result += c
    return result

# Advanced Unicode Normalization Attacks
def unicode_normalization_nfc(s):
    """Unicode NFC normalization for bypass testing"""
    import unicodedata
    return unicodedata.normalize('NFC', s)

def unicode_normalization_nfd(s):
    """Unicode NFD normalization for bypass testing"""
    import unicodedata
    return unicodedata.normalize('NFD', s)

def unicode_normalization_nfkc(s):
    """Unicode NFKC normalization for bypass testing"""
    import unicodedata
    return unicodedata.normalize('NFKC', s)

def unicode_normalization_nfkd(s):
    """Unicode NFKD normalization for bypass testing"""
    import unicodedata
    return unicodedata.normalize('NFKD', s)

# Advanced UTF Bypass Techniques
def utf8_null_byte_encode(s):
    """WAF Bypass: Insert null bytes in UTF-8"""
    result = ''
    for i, c in enumerate(s):
        result += c
        if i < len(s) - 1 and c.isalpha():  # Add null bytes between letters
            result += '\x00'
    return result

def utf8_bom_encode(s):
    """WAF Bypass: Add UTF-8 BOM markers"""
    return '\uFEFF' + s + '\uFEFF'

def utf32_encode(s):
    """UTF-32 encoding for bypass"""
    return s.encode('utf-32').hex()

def utf32_decode(s):
    """UTF-32 decoding"""
    return bytes.fromhex(s).decode('utf-32')

# Advanced Base Encoding Variants
def base36_encode(s):
    """Base36 encoding (0-9, A-Z)"""
    import base64
    # Convert to int and then to base36
    num = int.from_bytes(s.encode(), 'big')
    if num == 0:
        return '0'
    
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    result = ''
    while num > 0:
        num, remainder = divmod(num, 36)
        result = alphabet[remainder] + result
    return result

def base36_decode(s):
    """Base36 decoding"""
    num = 0
    for char in s.upper():
        if char.isdigit():
            num = num * 36 + int(char)
        else:
            num = num * 36 + (ord(char) - ord('A') + 10)
    
    # Convert back to bytes
    if num == 0:
        return ''
    
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big').decode()

def base62_encode(s):
    """Base62 encoding (0-9, A-Z, a-z)"""
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    num = int.from_bytes(s.encode(), 'big')
    if num == 0:
        return '0'
    
    result = ''
    while num > 0:
        num, remainder = divmod(num, 62)
        result = alphabet[remainder] + result
    return result

def base62_decode(s):
    """Base62 decoding"""
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    num = 0
    for char in s:
        num = num * 62 + alphabet.index(char)
    
    if num == 0:
        return ''
    
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big').decode()

# Advanced Compression Techniques
def bzip2_encode(s):
    """BZ2 compression + base64"""
    import bz2
    import base64
    compressed = bz2.compress(s.encode())
    return base64.b64encode(compressed).decode()

def bzip2_decode(s):
    """BZ2 decompression"""
    import bz2
    import base64
    compressed = base64.b64decode(s.encode())
    return bz2.decompress(compressed).decode()

def lzma_encode(s):
    """LZMA compression + base64"""
    import lzma
    import base64
    compressed = lzma.compress(s.encode())
    return base64.b64encode(compressed).decode()

def lzma_decode(s):
    """LZMA decompression"""
    import lzma
    import base64
    compressed = base64.b64decode(s.encode())
    return lzma.decompress(compressed).decode()

# Advanced Encoding Chains
def chain_encode_b64_url_double(s):
    """Chain: Base64 -> URL encode -> URL encode again"""
    step1 = base64.b64encode(s.encode()).decode()
    step2 = urllib.parse.quote(step1, safe='')
    return urllib.parse.quote(step2, base='')

def chain_decode_b64_url_double(s):
    """Reverse chain decoding"""
    step1 = urllib.parse.unquote(s)
    step2 = urllib.parse.unquote(step1)
    return base64.b64decode(step2.encode()).decode()

# Polyglot Encoding (works in multiple contexts)
def polyglot_js_php_encode(s):
    """Polyglot that works in both JS and PHP"""
    # Uses techniques that are valid in both languages
    encoded_chars = []
    for c in s:
        if c.isalpha():
            # Use chr() which exists in both JS and PHP (with different syntax)
            encoded_chars.append(f'chr({ord(c)})')
        else:
            encoded_chars.append(f'"{c}"')
    
    return ' . '.join(encoded_chars)  # PHP concatenation

def polyglot_html_js_encode(s):
    """Polyglot for HTML/JS contexts"""
    result = ''
    for c in s:
        # Mix HTML entities and JS escapes
        if ord(c) < 127:
            result += f'&#x{ord(c):x};'  # HTML hex entity
        else:
            result += f'\\u{ord(c):04x}'  # JS unicode escape
    return result

# Format String Attack Helpers
def format_string_encode(s):
    """Encode for format string attacks"""
    return s.replace('%', '%%').replace('{', '{{').replace('}', '}}')

def printf_format_encode(s):
    """Encode for printf-style format attacks"""
    result = ''
    for c in s:
        result += f'%{ord(c)}c'
    return result

# Binary Encoding Variants
def binary_msb_encode(s):
    """Binary with MSB first"""
    return ' '.join(format(ord(c), '08b') for c in s)

def binary_lsb_encode(s):
    """Binary with LSB first (reversed bits)"""
    return ' '.join(format(ord(c), '08b')[::-1] for c in s)

def binary_msb_decode(s):
    """Decode MSB binary"""
    return ''.join(chr(int(b, 2)) for b in s.split())

def binary_lsb_decode(s):
    """Decode LSB binary"""
    return ''.join(chr(int(b[::-1], 2)) for b in s.split())

# Null Byte Injection Techniques
def null_byte_terminate(s):
    """WAF Bypass: Add null byte termination"""
    return s + '\x00'

def null_byte_prefix(s):
    """WAF Bypass: Add null byte prefix"""
    return '\x00' + s

def null_byte_middle(s):
    """WAF Bypass: Insert null bytes in middle"""
    if len(s) < 2:
        return s + '\x00'
    mid = len(s) // 2
    return s[:mid] + '\x00' + s[mid:]

def null_byte_scatter(s):
    """WAF Bypass: Scatter null bytes throughout string"""
    result = ''
    for i, c in enumerate(s):
        result += c
        if i % 2 == 1 and i < len(s) - 1:  # Every other character
            result += '\x00'
    return result

def null_byte_hex_encode(s):
    """Null byte as %00 URL encoding"""
    return s.replace('\x00', '%00')

def null_byte_backslash_encode(s):
    """Null byte as \\0 C-style"""
    return s.replace('\x00', '\\0')

def null_byte_unicode_encode(s):
    """Null byte as \\u0000 Unicode"""
    return s.replace('\x00', '\\u0000')

def null_byte_decode(s):
    """Decode various null byte representations"""
    s = s.replace('%00', '\x00')
    s = s.replace('\\0', '\x00')
    s = s.replace('\\x00', '\x00')
    s = s.replace('\\u0000', '\x00')
    return s

# Terminal Escape Sequences (ANSI)
def terminal_escape_encode(s):
    """Add terminal escape sequences for evasion"""
    # Common ANSI escape sequences
    escapes = [
        '\x1b[0m',    # Reset
        '\x1b[31m',   # Red text
        '\x1b[32m',   # Green text
        '\x1b[33m',   # Yellow text
        '\x1b[1m',    # Bold
        '\x1b[2m',    # Dim
        '\x1b[7m',    # Reverse
        '\x1b[8m',    # Hidden
    ]
    
    import random
    result = ''
    for c in s:
        result += c
        if random.random() < 0.3:  # 30% chance to add escape
            result += random.choice(escapes)
    
    return result

def terminal_cursor_encode(s):
    """Insert cursor movement sequences"""
    movements = [
        '\x1b[A',     # Cursor up
        '\x1b[B',     # Cursor down
        '\x1b[C',     # Cursor right
        '\x1b[D',     # Cursor left
        '\x1b[H',     # Cursor home
        '\x1b[2J',    # Clear screen
        '\x1b[K',     # Clear line
    ]
    
    import random
    result = ''
    for i, c in enumerate(s):
        result += c
        if i % 3 == 0 and i > 0:  # Every 3rd character
            result += random.choice(movements)
    
    return result

def terminal_control_chars_encode(s):
    """WAF Bypass: Insert control characters"""
    control_chars = [
        '\x01',  # SOH (Start of Heading)
        '\x02',  # STX (Start of Text)  
        '\x03',  # ETX (End of Text)
        '\x04',  # EOT (End of Transmission)
        '\x05',  # ENQ (Enquiry)
        '\x06',  # ACK (Acknowledge)
        '\x07',  # BEL (Bell)
        '\x08',  # BS (Backspace)
        '\x09',  # HT (Horizontal Tab)
        '\x0A',  # LF (Line Feed)
        '\x0B',  # VT (Vertical Tab)
        '\x0C',  # FF (Form Feed)
        '\x0D',  # CR (Carriage Return)
        '\x0E',  # SO (Shift Out)
        '\x0F',  # SI (Shift In)
        '\x10',  # DLE (Data Link Escape)
        '\x11',  # DC1 (Device Control 1)
        '\x12',  # DC2 (Device Control 2)
        '\x13',  # DC3 (Device Control 3)
        '\x14',  # DC4 (Device Control 4)
        '\x15',  # NAK (Negative Acknowledge)
        '\x16',  # SYN (Synchronous Idle)
        '\x17',  # ETB (End of Transmission Block)
        '\x18',  # CAN (Cancel)
        '\x19',  # EM (End of Medium)
        '\x1A',  # SUB (Substitute)
        '\x1B',  # ESC (Escape)
        '\x1C',  # FS (File Separator)
        '\x1D',  # GS (Group Separator)
        '\x1E',  # RS (Record Separator)
        '\x1F',  # US (Unit Separator)
    ]
    
    import random
    result = ''
    for c in s:
        result += c
        if random.random() < 0.2:  # 20% chance
            result += random.choice(control_chars)
    
    return result

def terminal_escape_decode(s):
    """Remove ANSI escape sequences"""
    import re
    # Remove ANSI escape sequences
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', s)

# File Path Injection Techniques
def path_traversal_encode(s):
    """Add path traversal sequences"""
    traversals = ['../', '.\\', '....///', '....\\\\\\']
    import random
    prefix = random.choice(traversals) * random.randint(1, 5)
    return prefix + s

def file_extension_null_encode(s):
    """WAF Bypass: Null byte before file extension"""
    if '.' in s:
        parts = s.rsplit('.', 1)
        return parts[0] + '\x00.' + parts[1]
    return s + '\x00.txt'

def file_double_extension_encode(s):
    """Add double file extensions for bypass"""
    return s + '.jpg.php'

def file_case_bypass_encode(s):
    """Mix case in file extensions"""
    if '.' in s:
        parts = s.rsplit('.', 1)
        ext = parts[1]
        mixed_ext = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                          for i, c in enumerate(ext))
        return parts[0] + '.' + mixed_ext
    return s

# Advanced Control Character Variants
def control_char_hex_encode(s):
    """Encode control characters as hex"""
    result = ''
    for c in s:
        if ord(c) < 32 or ord(c) == 127:  # Control characters
            result += f'\\x{ord(c):02x}'
        else:
            result += c
    return result

def control_char_octal_encode(s):
    """Encode control characters as octal"""
    result = ''
    for c in s:
        if ord(c) < 32 or ord(c) == 127:  # Control characters
            result += f'\\{ord(c):03o}'
        else:
            result += c
    return result

def control_char_caret_encode(s):
    """Encode control characters in caret notation"""
    result = ''
    for c in s:
        if ord(c) < 32:  # Control characters 0-31
            result += f'^{chr(ord(c) + 64)}'
        elif ord(c) == 127:  # DEL
            result += '^?'
        else:
            result += c
    return result

# Windows/DOS Specific Bypasses
def dos_device_names_encode(s):
    """Add DOS device names for Windows bypass"""
    devices = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
               'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 
               'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
    import random
    return random.choice(devices) + '/' + s

def windows_alternate_stream_encode(s):
    """Add NTFS alternate data stream"""
    return s + ':hidden.txt'

def windows_short_name_encode(s):
    """Simulate Windows 8.3 short names"""
    if len(s) > 8:
        return s[:6] + '~1'
    return s

# Network Protocol Bypasses
def crlf_injection_encode(s):
    """CRLF injection for HTTP header splitting"""
    return s + '\r\n\r\nInjected-Header: malicious'

def http_parameter_pollution(s):
    """HTTP Parameter Pollution"""
    return s + '&' + s

def url_fragment_encode(s):
    """Add URL fragment for bypass"""
    return s + '#fragment'

def punycode_encode(s):
    """Punycode encoding for IDN bypass"""
    try:
        return s.encode('punycode').decode('ascii')
    except:
        return s

def punycode_decode(s):
    """Punycode decoding"""
    try:
        return s.encode('ascii').decode('punycode')
    except:
        return s

# Format String Injection Helpers
def format_string_printf(s):
    """Printf-style format string injection"""
    return s + '%x%x%x%x%x%x%x%x'

def format_string_positional(s):
    """Positional format string parameters"""
    return s + '%1$x%2$x%3$x%4$x'

def format_string_width(s):
    """Width specifier format strings"""
    return s + '%99999x'

# Unicode Bidirectional Override Attacks
def unicode_ltr_override(s):
    """Left-to-Right Override for bidirectional text attacks"""
    return '\u202D' + s + '\u202C'  # LTR override + text + pop directional formatting

def unicode_rtl_override(s):
    """Right-to-Left Override for bidirectional text attacks"""
    return '\u202E' + s + '\u202C'  # RTL override + text + pop directional formatting

def unicode_ltr_embed(s):
    """Left-to-Right Embedding"""
    return '\u202A' + s + '\u202C'  # LTR embed + text + pop directional formatting

def unicode_rtl_embed(s):
    """Right-to-Left Embedding"""
    return '\u202B' + s + '\u202C'  # RTL embed + text + pop directional formatting

# Advanced Unicode Attacks (Lesser Known)
def unicode_line_separator_inject(s):
    """Inject Unicode Line Separator (U+2028) - breaks JS/JSON parsing"""
    import random
    result = ''
    for i, c in enumerate(s):
        result += c
        if i % 3 == 0 and i > 0:
            result += '\u2028'  # Line Separator - breaks JavaScript
    return result

def unicode_paragraph_separator_inject(s):
    """Inject Unicode Paragraph Separator (U+2029) - breaks parsing"""
    import random
    result = ''
    for i, c in enumerate(s):
        result += c
        if i % 4 == 0 and i > 0:
            result += '\u2029'  # Paragraph Separator
    return result

def unicode_soft_hyphen_inject(s):
    """Inject Soft Hyphens (U+00AD) - invisible breaks"""
    result = ''
    for i, c in enumerate(s):
        result += c
        if i % 2 == 1:
            result += '\u00AD'  # Soft Hyphen - invisible but breaks word matching
    return result

def unicode_ideographic_description(s):
    """Use Ideographic Description Characters for obfuscation"""
    # These can be used to construct CJK characters dynamically
    desc_chars = ['\u2FF0', '\u2FF1', '\u2FF2', '\u2FF3', '\u2FF4', 
                  '\u2FF5', '\u2FF6', '\u2FF7', '\u2FF8', '\u2FF9', 
                  '\u2FFA', '\u2FFB']
    import random
    result = ''
    for c in s:
        result += c
        if random.random() < 0.3:
            result += random.choice(desc_chars)
    return result

def unicode_variation_selectors(s):
    """Add Variation Selectors to change glyph appearance"""
    # Variation selectors can change how characters are rendered
    selectors = ['\uFE00', '\uFE01', '\uFE02', '\uFE03', '\uFE04', 
                 '\uFE05', '\uFE06', '\uFE07', '\uFE08', '\uFE09', 
                 '\uFE0A', '\uFE0B', '\uFE0C', '\uFE0D', '\uFE0E', '\uFE0F']
    import random
    result = ''
    for c in s:
        result += c
        if c.isalpha():
            result += random.choice(selectors)
    return result

def unicode_tag_characters(s):
    """Use Unicode Tag Characters for steganography (as escape sequences)"""
    # Tag characters (U+E0000-U+E007F) are invisible but preserved
    # Output as escape sequences since these are very high codepoints
    import random
    result = ''
    for c in s:
        result += c
        if random.random() < 0.2:
            tag_code = 0xE0000 + random.randint(32, 126)
            result += f'\\U{tag_code:08X}'
    return result

def unicode_private_use_encode(s):
    """Encode using Private Use Area characters"""
    # Map ASCII to Private Use Area (U+E000-U+F8FF)
    result = ''
    for c in s:
        if ord(c) < 128:  # ASCII range
            result += chr(0xE000 + ord(c))  # Map to Private Use Area
        else:
            result += c
    return result

def unicode_private_use_decode(s):
    """Decode from Private Use Area"""
    result = ''
    for c in s:
        code = ord(c)
        if 0xE000 <= code <= 0xE07F:  # Our mapped ASCII range
            result += chr(code - 0xE000)
        else:
            result += c
    return result

def unicode_surrogate_pairs_encode(s):
    """Create surrogate pair representations as escape sequences for UTF-16 attacks"""
    result = ''
    for c in s:
        if ord(c) < 128:
            # Create a surrogate pair representation as escape sequences
            high_surrogate = 0xD800 + (ord(c) % 0x400)
            low_surrogate = 0xDC00 + ((ord(c) * 7) % 0x400)
            result += f'\\u{high_surrogate:04X}\\u{low_surrogate:04X}'
        else:
            result += c
    return result

def unicode_canonical_confusion(s):
    """Use canonically equivalent but visually different characters"""
    # Characters that normalize to the same thing but look different
    confusion_map = {
        'A': ['Α', 'А', 'Ａ'],  # Greek Alpha, Cyrillic A, Fullwidth A
        'a': ['а', 'ａ', 'α'],  # Cyrillic a, Fullwidth a, Greek alpha
        'B': ['Β', 'В', 'Ｂ'],  # Greek Beta, Cyrillic B, Fullwidth B
        'E': ['Ε', 'Е', 'Ｅ'],  # Greek Epsilon, Cyrillic E, Fullwidth E
        'H': ['Η', 'Н', 'Ｈ'],  # Greek Eta, Cyrillic H, Fullwidth H
        'I': ['Ι', 'І', 'Ｉ'],  # Greek Iota, Cyrillic I, Fullwidth I
        'K': ['Κ', 'К', 'Ｋ'],  # Greek Kappa, Cyrillic K, Fullwidth K
        'M': ['Μ', 'М', 'Ｍ'],  # Greek Mu, Cyrillic M, Fullwidth M
        'N': ['Ν', 'Ν', 'Ｎ'],  # Greek Nu, Cyrillic N, Fullwidth N
        'O': ['Ο', 'О', 'Ｏ'],  # Greek Omicron, Cyrillic O, Fullwidth O
        'P': ['Ρ', 'Р', 'Ｐ'],  # Greek Rho, Cyrillic P, Fullwidth P
        'T': ['Τ', 'Т', 'Ｔ'],  # Greek Tau, Cyrillic T, Fullwidth T
        'X': ['Χ', 'Х', 'Ｘ'],  # Greek Chi, Cyrillic X, Fullwidth X
        'Y': ['Υ', 'У', 'Ｙ'],  # Greek Upsilon, Cyrillic Y, Fullwidth Y
        'Z': ['Ζ', 'Ζ', 'Ｚ'],  # Greek Zeta, Cyrillic Z, Fullwidth Z
    }
    
    import random
    result = ''
    for c in s:
        if c in confusion_map:
            result += random.choice(confusion_map[c])
        else:
            result += c
    return result

def unicode_bom_injection(s):
    """Inject different Byte Order Marks (safe versions)"""
    boms = [
        '\uFEFF',  # UTF-8 BOM
        '\uFFFE',  # Reversed UTF-8 BOM (note: this is not a valid UTF-8 BOM but used for testing)
    ]
    import random
    return random.choice(boms) + s + random.choice(boms)

def unicode_grapheme_cluster_attack(s):
    """Create complex grapheme clusters to confuse parsers"""
    # Combining characters that can create complex clusters
    combining_chars = [
        '\u0300', '\u0301', '\u0302', '\u0303',  # Combining accents
        '\u0327', '\u0328', '\u0329', '\u032A',  # Combining below
        '\u20D0', '\u20D1', '\u20D2', '\u20D3',  # Combining enclosing
        '\u1AB0', '\u1AB1', '\u1AB2', '\u1AB3',  # Combining doubling
    ]
    
    import random
    result = ''
    for c in s:
        result += c
        # Add multiple combining characters to create complex clusters
        if c.isalpha():
            for _ in range(random.randint(1, 4)):
                result += random.choice(combining_chars)
    return result

def unicode_script_mixing_attack(s):
    """Mix scripts to create spoofed text"""
    # Mix Latin with similar-looking characters from other scripts
    script_mix = {
        'a': ['а', 'ɑ', 'α', 'ａ'],  # Cyrillic, IPA, Greek, Fullwidth
        'e': ['е', 'ε', 'ｅ'],        # Cyrillic, Greek, Fullwidth  
        'o': ['о', 'ο', 'ο', 'ｏ'],  # Cyrillic, Greek, Greek, Fullwidth
        'p': ['р', 'ρ', 'ｐ'],        # Cyrillic, Greek, Fullwidth
        'c': ['с', 'ϲ', 'ｃ'],        # Cyrillic, Greek, Fullwidth
        'x': ['х', 'χ', 'ｘ'],        # Cyrillic, Greek, Fullwidth
        'y': ['у', 'γ', 'ｙ'],        # Cyrillic, Greek, Fullwidth
    }
    
    import random
    result = ''
    for c in s:
        if c.lower() in script_mix:
            if c.isupper():
                options = [opt.upper() for opt in script_mix[c.lower()] if opt.upper() != opt]
                if options:
                    result += random.choice(options)
                else:
                    result += c
            else:
                result += random.choice(script_mix[c.lower()])
        else:
            result += c
    return result

def unicode_format_characters_inject(s):
    """Inject Unicode format characters"""
    format_chars = [
        '\u061C',  # Arabic Letter Mark
        '\u180E',  # Mongolian Vowel Separator
        '\u200B',  # Zero Width Space
        '\u200C',  # Zero Width Non-Joiner
        '\u200D',  # Zero Width Joiner
        '\u2060',  # Word Joiner
        '\u2061',  # Function Application
        '\u2062',  # Invisible Times
        '\u2063',  # Invisible Separator
        '\u2064',  # Invisible Plus
        '\uFEFF',  # Zero Width No-Break Space
    ]
    
    import random
    result = ''
    for i, c in enumerate(s):
        result += c
        if i < len(s) - 1:
            result += random.choice(format_chars)
    return result

# Show examples function
def show_examples():
    """Show all encoding techniques grouped by family"""
    examples = """
🔥 CYBERSECURITY ENCODER - ALL TECHNIQUES 🔥

═══════════════════════════════════════════════════════════════════
📋 COMMON WAF BYPASSES (OWASP Priority)
═══════════════════════════════════════════════════════════════════

--double-url              echo "alert(1)" | python3 encoder.py --double-url
--triple-url              echo "alert(1)" | python3 encoder.py --triple-url
--urlencode               echo "alert(1)" | python3 encoder.py --urlencode
--html                    echo "<script>" | python3 encoder.py --html
--html-named              echo "<script>" | python3 encoder.py --html-named
--html-hex                echo "<script>" | python3 encoder.py --html-hex
--html-decimal            echo "<script>" | python3 encoder.py --html-decimal
--html-entity-mixed       echo "<script>" | python3 encoder.py --html-entity-mixed
--xml                     echo "<script>" | python3 encoder.py --xml
--xml-cdata               echo "<script>" | python3 encoder.py --xml-cdata

═══════════════════════════════════════════════════════════════════
💉 SQL INJECTION BYPASSES
═══════════════════════════════════════════════════════════════════

--sql-char                echo "UNION SELECT" | python3 encoder.py --sql-char
--sql-hex                 echo "UNION SELECT" | python3 encoder.py --sql-hex
--sql-concat-obfuscate    echo "admin OR 1=1" | python3 encoder.py --sql-concat-obfuscate
--sql-comment-obfuscate   echo "SELECT password" | python3 encoder.py --sql-comment-obfuscate

═══════════════════════════════════════════════════════════════════
🌐 JAVASCRIPT/JSON BYPASSES
═══════════════════════════════════════════════════════════════════

--js-unicode              echo "alert(1)" | python3 encoder.py --js-unicode
--js-hex                  echo "alert(1)" | python3 encoder.py --js-hex
--js-fromcharcode         echo "alert(1)" | python3 encoder.py --js-fromcharcode
--js-string-split         echo "alert(1)" | python3 encoder.py --js-string-split
--js-template-literal     echo "alert(1)" | python3 encoder.py --js-template-literal
--json                    echo "alert(1)" | python3 encoder.py --json

═══════════════════════════════════════════════════════════════════
🐍 PYTHON SANDBOX ESCAPES
═══════════════════════════════════════════════════════════════════

--funny-chr               echo "__import__('os')" | python3 encoder.py --funny-chr
--funny-eval              echo "__import__('os')" | python3 encoder.py --funny-eval
--funny-simple            echo "__import__('os')" | python3 encoder.py --funny-simple
--funny-import            echo "os" | python3 encoder.py --funny-import
--funny-getattr           echo "system" | python3 encoder.py --funny-getattr
--funny-italic            echo "__import__('os')" | python3 encoder.py --funny-italic
--funny-any               echo "payload" | python3 encoder.py --funny-any --funny-function="eval"

═══════════════════════════════════════════════════════════════════
🔤 UNICODE OBFUSCATION (Mathematical)
═══════════════════════════════════════════════════════════════════

--math-unicode            echo "script" | python3 encoder.py --math-unicode
--math-mono               echo "script" | python3 encoder.py --math-mono
--math-unicode-script     echo "script" | python3 encoder.py --math-unicode-script
--math-unicode-fraktur    echo "script" | python3 encoder.py --math-unicode-fraktur
--math-unicode-double-struck echo "script" | python3 encoder.py --math-unicode-double-struck
--fullwidth               echo "script" | python3 encoder.py --fullwidth

═══════════════════════════════════════════════════════════════════
🎭 UNICODE CONFUSION ATTACKS
═══════════════════════════════════════════════════════════════════

--unicode-homograph       echo "SELECT" | python3 encoder.py --unicode-homograph
--unicode-confusables     echo "script" | python3 encoder.py --unicode-confusables
--unicode-canonical-confusion echo "script" | python3 encoder.py --unicode-canonical-confusion
--unicode-script-mixing   echo "script" | python3 encoder.py --unicode-script-mixing

═══════════════════════════════════════════════════════════════════
📝 UNICODE BIDIRECTIONAL ATTACKS
═══════════════════════════════════════════════════════════════════

--unicode-ltr-override    echo "script" | python3 encoder.py --unicode-ltr-override
--unicode-rtl-override    echo "script" | python3 encoder.py --unicode-rtl-override
--unicode-ltr-embed       echo "script" | python3 encoder.py --unicode-ltr-embed
--unicode-rtl-embed       echo "script" | python3 encoder.py --unicode-rtl-embed

═══════════════════════════════════════════════════════════════════
👻 INVISIBLE UNICODE ATTACKS
═══════════════════════════════════════════════════════════════════

--invisible               echo "script" | python3 encoder.py --invisible
--invisible-separator     echo "script" | python3 encoder.py --invisible-separator
--invisible-bidirectional echo "script" | python3 encoder.py --invisible-bidirectional
--unicode-soft-hyphen     echo "script" | python3 encoder.py --unicode-soft-hyphen
--unicode-format-characters echo "script" | python3 encoder.py --unicode-format-characters

═══════════════════════════════════════════════════════════════════
💥 ADVANCED UNICODE EXPLOITS (Rare)
═══════════════════════════════════════════════════════════════════

--unicode-line-separator  echo "script" | python3 encoder.py --unicode-line-separator
--unicode-paragraph-separator echo "script" | python3 encoder.py --unicode-paragraph-separator
--unicode-ideographic-description echo "script" | python3 encoder.py --unicode-ideographic-description
--unicode-variation-selectors echo "script" | python3 encoder.py --unicode-variation-selectors
--unicode-tag-characters  echo "script" | python3 encoder.py --unicode-tag-characters
--unicode-private-use     echo "script" | python3 encoder.py --unicode-private-use
--unicode-surrogate-pairs echo "script" | python3 encoder.py --unicode-surrogate-pairs
--unicode-bom-injection   echo "script" | python3 encoder.py --unicode-bom-injection
--unicode-grapheme-cluster echo "script" | python3 encoder.py --unicode-grapheme-cluster

═══════════════════════════════════════════════════════════════════
🎯 LEADING ZEROS BYPASS (WAF Evasion)
═══════════════════════════════════════════════════════════════════

--html-hex-leading-zeros  echo "alert(1)" | python3 encoder.py --html-hex-leading-zeros
--html-decimal-leading-zeros echo "alert(1)" | python3 encoder.py --html-decimal-leading-zeros
--xml-hex-leading-zeros   echo "SELECT" | python3 encoder.py --xml-hex-leading-zeros
--xml-decimal-leading-zeros echo "SELECT" | python3 encoder.py --xml-decimal-leading-zeros
--unicode-escape-leading-zeros echo "script" | python3 encoder.py --unicode-escape-leading-zeros
--unicode-traditional-leading-zeros echo "script" | python3 encoder.py --unicode-traditional-leading-zeros
--js-unicode-leading-zeros echo "alert(1)" | python3 encoder.py --js-unicode-leading-zeros
--hex-escape-leading-zeros echo "script" | python3 encoder.py --hex-escape-leading-zeros

═══════════════════════════════════════════════════════════════════
🔗 MULTIPLE ENCODING LAYERS
═══════════════════════════════════════════════════════════════════

--html-unicode-double     echo "alert(1)" | python3 encoder.py --html-unicode-double
--unicode-html-double     echo "alert(1)" | python3 encoder.py --unicode-html-double
--url-html-double         echo "alert(1)" | python3 encoder.py --url-html-double
--html-url-double         echo "alert(1)" | python3 encoder.py --html-url-double
--triple-url-html-unicode echo "payload" | python3 encoder.py --triple-url-html-unicode

═══════════════════════════════════════════════════════════════════
🗄️ ADVANCED SQL OBFUSCATION
═══════════════════════════════════════════════════════════════════

--sql-char-hex-mixed      echo "SELECT" | python3 encoder.py --sql-char-hex-mixed
--sql-unhex               echo "SELECT" | python3 encoder.py --sql-unhex
--sql-hex-literal         echo "SELECT" | python3 encoder.py --sql-hex-literal
--sql-binary              echo "SELECT" | python3 encoder.py --sql-binary
--sql-ascii               echo "SELECT" | python3 encoder.py --sql-ascii

═══════════════════════════════════════════════════════════════════
⚡ JAVASCRIPT ADVANCED
═══════════════════════════════════════════════════════════════════

--js-fromcharcode-split   echo "alert(1)" | python3 encoder.py --js-fromcharcode-split
--js-eval-fromcharcode    echo "alert(1)" | python3 encoder.py --js-eval-fromcharcode
--js-unescape             echo "alert(1)" | python3 encoder.py --js-unescape

═══════════════════════════════════════════════════════════════════
🐘 PHP ADVANCED OBFUSCATION
═══════════════════════════════════════════════════════════════════

--php-chr-hex-mixed       echo "system" | python3 encoder.py --php-chr-hex-mixed
--php-pack                echo "system" | python3 encoder.py --php-pack
--php-hex2bin             echo "system" | python3 encoder.py --php-hex2bin

═══════════════════════════════════════════════════════════════════
💻 POWERSHELL OBFUSCATION
═══════════════════════════════════════════════════════════════════

--powershell-char-array   echo "Get-Process" | python3 encoder.py --powershell-char-array
--powershell-format       echo "Get-Process" | python3 encoder.py --powershell-format

═══════════════════════════════════════════════════════════════════
🐧 LINUX/BASH ESCAPING
═══════════════════════════════════════════════════════════════════

--bash-dollar             echo "whoami" | python3 encoder.py --bash-dollar
--bash-printf             echo "whoami" | python3 encoder.py --bash-printf

═══════════════════════════════════════════════════════════════════
📄 ADVANCED XML TECHNIQUES
═══════════════════════════════════════════════════════════════════

--xml-cdata-advanced      echo "SELECT" | python3 encoder.py --xml-cdata-advanced
--xml-processing-instruction echo "SELECT" | python3 encoder.py --xml-processing-instruction

═══════════════════════════════════════════════════════════════════
📊 ADVANCED BASE64 VARIATIONS
═══════════════════════════════════════════════════════════════════

--base64-chunked          echo "payload" | python3 encoder.py --base64-chunked
--base64-atob             echo "payload" | python3 encoder.py --base64-atob

═══════════════════════════════════════════════════════════════════
🎨 ADVANCED CASE OBFUSCATION
═══════════════════════════════════════════════════════════════════

--case-unicode-mixed      echo "SELECT" | python3 encoder.py --case-unicode-mixed

═══════════════════════════════════════════════════════════════════
🌪️ ZALGO TEXT FUZZING
═══════════════════════════════════════════════════════════════════

--unicode-zalgo           echo "script" | python3 encoder.py --unicode-zalgo
--unicode-zalgo-crazy     echo "script" | python3 encoder.py --unicode-zalgo-crazy --zalgo-craziness=5

═══════════════════════════════════════════════════════════════════
🔢 BASE ENCODINGS
═══════════════════════════════════════════════════════════════════

--base64                  echo "script" | python3 encoder.py --base64
--b64url                  echo "script" | python3 encoder.py --b64url
--base32                  echo "script" | python3 encoder.py --base32
--base58                  echo "script" | python3 encoder.py --base58
--base36                  echo "script" | python3 encoder.py --base36
--base62                  echo "script" | python3 encoder.py --base62
--base85                  echo "script" | python3 encoder.py --base85

═══════════════════════════════════════════════════════════════════
🧮 NUMERIC ENCODINGS
═══════════════════════════════════════════════════════════════════

--hex                     echo "script" | python3 encoder.py --hex
--ascii-hex               echo "script" | python3 encoder.py --ascii-hex
--octal                   echo "script" | python3 encoder.py --octal
--binary                  echo "script" | python3 encoder.py --binary
--binary-msb              echo "script" | python3 encoder.py --binary-msb
--binary-lsb              echo "script" | python3 encoder.py --binary-lsb

═══════════════════════════════════════════════════════════════════
🌍 UTF ENCODING VARIANTS
═══════════════════════════════════════════════════════════════════

--utf7                    echo "script" | python3 encoder.py --utf7
--utf7-plus               echo "script" | python3 encoder.py --utf7-plus
--utf8-overlong-manual    echo "script" | python3 encoder.py --utf8-overlong-manual
--utf8-null-byte          echo "script" | python3 encoder.py --utf8-null-byte
--utf8-bom                echo "script" | python3 encoder.py --utf8-bom
--utf16                   echo "script" | python3 encoder.py --utf16
--utf16-mixed-endian      echo "script" | python3 encoder.py --utf16-mixed-endian
--utf32                   echo "script" | python3 encoder.py --utf32
--unicode                 echo "script" | python3 encoder.py --unicode
--unicode-mixed           echo "script" | python3 encoder.py --unicode-mixed
--unicode-overlong        echo "script" | python3 encoder.py --unicode-overlong

═══════════════════════════════════════════════════════════════════
💀 NULL BYTE INJECTION
═══════════════════════════════════════════════════════════════════

--null-byte-terminate     echo "script.php" | python3 encoder.py --null-byte-terminate
--null-byte-prefix        echo "script.php" | python3 encoder.py --null-byte-prefix
--null-byte-middle        echo "script.php" | python3 encoder.py --null-byte-middle
--null-byte-scatter       echo "script.php" | python3 encoder.py --null-byte-scatter
--null-byte-hex           echo "script\\x00.php" | python3 encoder.py --null-byte-hex
--null-byte-backslash     echo "script\\x00.php" | python3 encoder.py --null-byte-backslash
--null-byte-unicode       echo "script\\x00.php" | python3 encoder.py --null-byte-unicode

═══════════════════════════════════════════════════════════════════
💻 TERMINAL/CONTROL CHARS
═══════════════════════════════════════════════════════════════════

--terminal-escape         echo "script" | python3 encoder.py --terminal-escape
--terminal-cursor         echo "script" | python3 encoder.py --terminal-cursor
--terminal-control-chars  echo "script" | python3 encoder.py --terminal-control-chars
--control-char-hex        echo "script" | python3 encoder.py --control-char-hex
--control-char-octal      echo "script" | python3 encoder.py --control-char-octal
--control-char-caret      echo "script" | python3 encoder.py --control-char-caret

═══════════════════════════════════════════════════════════════════
📁 FILE PATH INJECTION
═══════════════════════════════════════════════════════════════════

--path-traversal          echo "file.txt" | python3 encoder.py --path-traversal
--file-extension-null     echo "script.php" | python3 encoder.py --file-extension-null
--file-double-extension   echo "script.php" | python3 encoder.py --file-double-extension
--file-case-bypass        echo "script.PHP" | python3 encoder.py --file-case-bypass

═══════════════════════════════════════════════════════════════════
🪟 WINDOWS SPECIFIC
═══════════════════════════════════════════════════════════════════

--dos-device-names        echo "file.txt" | python3 encoder.py --dos-device-names
--windows-alternate-stream echo "file.txt" | python3 encoder.py --windows-alternate-stream
--windows-short-name      echo "longfilename.txt" | python3 encoder.py --windows-short-name
--windows1252             echo "script" | python3 encoder.py --windows1252

═══════════════════════════════════════════════════════════════════
🌐 NETWORK PROTOCOLS
═══════════════════════════════════════════════════════════════════

--crlf-injection          echo "Header" | python3 encoder.py --crlf-injection
--http-parameter-pollution echo "param=value" | python3 encoder.py --http-parameter-pollution
--url-fragment            echo "page.php" | python3 encoder.py --url-fragment
--punycode                echo "test" | python3 encoder.py --punycode

═══════════════════════════════════════════════════════════════════
🔧 PHP SPECIFIC
═══════════════════════════════════════════════════════════════════

--php-chr-concat          echo "system" | python3 encoder.py --php-chr-concat
--php-hex                 echo "system" | python3 encoder.py --php-hex
--php-base64-encode-custom echo "system" | python3 encoder.py --php-base64-encode-custom
--php-serialize           echo "payload" | python3 encoder.py --php-serialize

═══════════════════════════════════════════════════════════════════
⚙️ CASE MANIPULATION
═══════════════════════════════════════════════════════════════════

--case-alternating        echo "SELECT" | python3 encoder.py --case-alternating
--case-random             echo "SELECT" | python3 encoder.py --case-random
--case-vowel-upper        echo "SELECT" | python3 encoder.py --case-vowel-upper
--case-consonant-upper    echo "SELECT" | python3 encoder.py --case-consonant-upper
--mixed-case              echo "SELECT" | python3 encoder.py --mixed-case

═══════════════════════════════════════════════════════════════════
🎨 FUN ENCODINGS
═══════════════════════════════════════════════════════════════════

--emoji                   echo "alert(1)" | python3 encoder.py --emoji
--morse                   echo "SOS" | python3 encoder.py --morse

═══════════════════════════════════════════════════════════════════
🔐 CLASSIC CIPHERS
═══════════════════════════════════════════════════════════════════

--rot13                   echo "secret" | python3 encoder.py --rot13
--rot47                   echo "secret" | python3 encoder.py --rot47
--caesar                  echo "secret" | python3 encoder.py --caesar --shift=5
--atbash                  echo "secret" | python3 encoder.py --atbash
--vigenere                echo "secret" | python3 encoder.py --vigenere --vigenere-key="KEY"
--xor                     echo "secret" | python3 encoder.py --xor --xor-key=42

═══════════════════════════════════════════════════════════════════
📦 COMPRESSION
═══════════════════════════════════════════════════════════════════

--gzip                    echo "payload" | python3 encoder.py --gzip
--bzip2                   echo "payload" | python3 encoder.py --bzip2
--lzma                    echo "payload" | python3 encoder.py --lzma

═══════════════════════════════════════════════════════════════════
🔗 ENCODING CHAINS
═══════════════════════════════════════════════════════════════════

--chain-b64-url-double    echo "payload" | python3 encoder.py --chain-b64-url-double

═══════════════════════════════════════════════════════════════════
🎪 POLYGLOT TECHNIQUES
═══════════════════════════════════════════════════════════════════

--polyglot-js-php         echo "system('whoami')" | python3 encoder.py --polyglot-js-php
--polyglot-html-js        echo "<script>" | python3 encoder.py --polyglot-html-js

═══════════════════════════════════════════════════════════════════
📊 FORMAT STRING
═══════════════════════════════════════════════════════════════════

--format-string           echo "payload" | python3 encoder.py --format-string
--printf-format           echo "payload" | python3 encoder.py --printf-format
--format-string-printf    echo "payload" | python3 encoder.py --format-string-printf
--format-string-positional echo "payload" | python3 encoder.py --format-string-positional
--format-string-width     echo "payload" | python3 encoder.py --format-string-width

═══════════════════════════════════════════════════════════════════
🔍 OTHER TECHNIQUES
═══════════════════════════════════════════════════════════════════

--ldap                    echo "admin" | python3 encoder.py --ldap
--css                     echo "script" | python3 encoder.py --css
--powershell              echo "Get-Process" | python3 encoder.py --powershell
--backslash               echo "script" | python3 encoder.py --backslash
--pickle-hex              echo "payload" | python3 encoder.py --pickle-hex

═══════════════════════════════════════════════════════════════════
🧮 HASH FUNCTIONS
═══════════════════════════════════════════════════════════════════

--md5                     echo "password" | python3 encoder.py --md5
--sha1                    echo "password" | python3 encoder.py --sha1
--sha256                  echo "password" | python3 encoder.py --sha256

═══════════════════════════════════════════════════════════════════
🔧 USAGE NOTES
═══════════════════════════════════════════════════════════════════

• Use -d flag to decode: python3 encoder.py --base64 -d
• Use -f for files: python3 encoder.py --base64 -f input.txt
• Chain encodings: echo "test" | python3 encoder.py --base64 | python3 encoder.py --double-url
• Zalgo options: --zalgo-craziness=1-10 --zalgo-above --zalgo-below --zalgo-overlay
• Custom functions: --funny-any --funny-function="system"

Total: 170+ encoding techniques for advanced penetration testing!
"""
    print(examples)
    sys.exit(0)

def unicode_homograph_encode(s):
    """WAF Bypass: Replace with visually similar Unicode characters"""
    # Cyrillic and other look-alikes
    homographs = {
        'a': 'а', 'c': 'с', 'e': 'е', 'o': 'о', 'p': 'р', 'x': 'х', 'y': 'у',
        'A': 'А', 'B': 'В', 'C': 'С', 'E': 'Е', 'H': 'Н', 'K': 'К', 'M': 'М',
        'O': 'О', 'P': 'Р', 'T': 'Т', 'X': 'Х', 'У': 'У'
    }
    return ''.join(homographs.get(c, c) for c in s)

# Emoji Encoding (WAF Bypass: Unexpected encoding)
def emoji_encode(s):
    """WAF Bypass: Convert to emoji representation"""
    # Map characters to similar-looking emojis
    emoji_map = {
        'a': '🅰️', 'b': '🅱️', 'o': '⭕', 'i': 'ℹ️', 'x': '❌', 
        '0': '0️⃣', '1': '1️⃣', '2': '2️⃣', '3': '3️⃣', '4': '4️⃣',
        '5': '5️⃣', '6': '6️⃣', '7': '7️⃣', '8': '8️⃣', '9': '9️⃣',
        '!': '❗', '?': '❓', '*': '⭐', '+': '➕', '-': '➖'
    }
    return ''.join(emoji_map.get(c.lower(), c) for c in s)

# Advanced UTF Encoding WAF Bypasses
def utf7_plus_encode(s):
    """WAF Bypass: UTF-7 with explicit plus encoding"""
    try:
        return s.encode('utf-7').decode('ascii').replace('+', '%2B')
    except:
        return s

def utf8_overlong_manual(s):
    """WAF Bypass: Manual overlong UTF-8 sequences"""
    result = ''
    for c in s:
        if ord(c) < 128:
            # Create overlong 3-byte sequence for ASCII
            byte1 = 0xE0 | ((ord(c) >> 12) & 0x0F)
            byte2 = 0x80 | ((ord(c) >> 6) & 0x3F)  
            byte3 = 0x80 | (ord(c) & 0x3F)
            result += f'%{byte1:02X}%{byte2:02X}%{byte3:02X}'
        else:
            result += urllib.parse.quote(c)
    return result

def utf16_mixed_endian(s):
    """WAF Bypass: Mix UTF-16 BE and LE encoding"""
    result = ''
    for i, c in enumerate(s):
        if i % 2 == 0:
            # Big Endian
            utf16_bytes = c.encode('utf-16be')
        else:
            # Little Endian  
            utf16_bytes = c.encode('utf-16le')
        result += ''.join(f'%{b:02X}' for b in utf16_bytes)
    return result

# Advanced Invisible Unicode WAF Bypasses
def invisible_separator_encode(s):
    """WAF Bypass: Insert invisible separators between every character"""
    separators = [
        '\u2028',  # Line Separator
        '\u2029',  # Paragraph Separator
        '\u200B',  # Zero Width Space
        '\u200C',  # Zero Width Non-Joiner
        '\u200D',  # Zero Width Joiner
        '\u2060',  # Word Joiner
        '\uFEFF',  # Zero Width No-Break Space
    ]
    import random
    result = ''
    for i, c in enumerate(s):
        result += c
        if i < len(s) - 1:
            result += random.choice(separators)
    return result

def invisible_bidirectional_encode(s):
    """WAF Bypass: Insert bidirectional override characters"""
    bidi_chars = [
        '\u202A',  # Left-to-Right Embedding
        '\u202B',  # Right-to-Left Embedding  
        '\u202C',  # Pop Directional Formatting
        '\u202D',  # Left-to-Right Override
        '\u202E',  # Right-to-Left Override
    ]
    import random
    result = '\u202D'  # Start with LTR override
    for c in s:
        result += c + random.choice(bidi_chars)
    result += '\u202C'  # End with pop formatting
    return result

# HTML/XML WAF Bypasses
def html_entity_mixed_encode(s):
    """WAF Bypass: Mix named, hex, and decimal HTML entities"""
    import random
    result = ''
    for c in s:
        choice = random.randint(1, 3)
        if choice == 1:
            result += f'&#{ord(c)};'  # Decimal
        elif choice == 2:
            result += f'&#x{ord(c):x};'  # Hex
        else:
            # Named entities for common chars
            named = {'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;'}
            result += named.get(c, f'&#{ord(c)};')
    return result

def xml_cdata_encode(s):
    """WAF Bypass: Wrap in XML CDATA sections"""
    return f'<![CDATA[{s}]]>'

# SQL Injection WAF Bypasses
def sql_comment_obfuscate(s):
    """WAF Bypass: Insert SQL comments randomly"""
    import random
    result = ''
    for i, c in enumerate(s):
        result += c
        if c == ' ' and random.random() < 0.3:  # 30% chance
            result += random.choice(['/**/'])  # More comments could be added
    return result

def sql_concat_obfuscate(s):
    """WAF Bypass: Break string into CONCAT() pieces"""
    if len(s) < 3:
        return f"'{s}'"
    
    # Split into random pieces
    import random
    pieces = []
    i = 0
    while i < len(s):
        chunk_size = random.randint(1, 3)
        pieces.append(s[i:i+chunk_size])
        i += chunk_size
    
    return 'CONCAT(' + ','.join(f"'{piece}'" for piece in pieces) + ')'

# JavaScript WAF Bypasses
def js_string_split_encode(s):
    """WAF Bypass: Use JavaScript string splitting"""
    return f"'{s}'.split('').join('')"

def js_fromcharcode_encode(s):
    """WAF Bypass: JavaScript String.fromCharCode()"""
    char_codes = ','.join(str(ord(c)) for c in s)
    return f'String.fromCharCode({char_codes})'

def js_template_literal_encode(s):
    """WAF Bypass: Use template literals with expressions"""
    result = '`'
    for c in s:
        if c.isalpha():
            result += f'${{String.fromCharCode({ord(c)})}}'
        else:
            result += c
    result += '`'
    return result

# PHP WAF Bypasses  
def php_chr_concat_encode(s):
    """WAF Bypass: PHP chr() concatenation"""
    return '.'.join(f'chr({ord(c)})' for c in s)

def php_hex_encode(s):
    """WAF Bypass: PHP hex string"""
    return '0x' + s.encode().hex()

def php_base64_encode_custom(s):
    """WAF Bypass: PHP base64 with decode"""
    import base64
    encoded = base64.b64encode(s.encode()).decode()
    return f'base64_decode("{encoded}")'

# Advanced Mathematical Unicode Variants
def math_unicode_script_encode(s):
    """Mathematical Script Unicode"""
    # Script uppercase: U+1D49C-U+1D4B5, lowercase: U+1D4B6-U+1D4CF
    result = ''
    for c in s:
        if 'A' <= c <= 'Z':
            result += chr(0x1D49C + (ord(c) - ord('A')))
        elif 'a' <= c <= 'z':
            result += chr(0x1D4B6 + (ord(c) - ord('a')))
        else:
            result += c
    return result

def math_unicode_fraktur_encode(s):
    """Mathematical Fraktur Unicode (Gothic)"""
    # Fraktur uppercase: U+1D504-U+1D51D, lowercase: U+1D51E-U+1D537
    result = ''
    for c in s:
        if 'A' <= c <= 'Z':
            result += chr(0x1D504 + (ord(c) - ord('A')))
        elif 'a' <= c <= 'z':
            result += chr(0x1D51E + (ord(c) - ord('a')))
        else:
            result += c
    return result

def math_unicode_double_struck_encode(s):
    """Mathematical Double-Struck Unicode"""
    # Double-struck uppercase: U+1D538-U+1D551, lowercase: U+1D552-U+1D56B
    result = ''
    for c in s:
        if 'A' <= c <= 'Z':
            result += chr(0x1D538 + (ord(c) - ord('A')))
        elif 'a' <= c <= 'z':
            result += chr(0x1D552 + (ord(c) - ord('a')))
        else:
            result += c
    return result

# Decode functions for new encodings
def decode_case_variations(s):
    """Decode case variations back to lowercase"""
    return s.lower()

def decode_zalgo(s):
    """Remove zalgo/combining marks"""
    import unicodedata
    return ''.join(c for c in s if not unicodedata.combining(c))

def decode_homograph(s):
    """Convert homograph characters back"""
    # Reverse mapping
    homographs = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
        'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
        'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'У': 'Y'
    }
    return ''.join(homographs.get(c, c) for c in s)

# Decoders (restored)
def decode_url(s): return urllib.parse.unquote(s)
def decode_xml(s): return re.sub(r'&#x([0-9A-Fa-f]+)', lambda m: chr(int(m.group(1), 16)), s)
def decode_base85(s): return base64.a85decode(s.encode()).decode()
def decode_base64(s): return base64.b64decode(s.encode()).decode()
def decode_b64_url(s): return base64.urlsafe_b64decode(s.encode()).decode()
def decode_ascii_hex(s): return bytes.fromhex(s).decode()
def decode_hex(s): return bytes.fromhex(s).decode()
def decode_octal(s): return ''.join(chr(int(c, 8)) for c in s.split())
def decode_binary(s): return ''.join(chr(int(b, 2)) for b in s.split())
def decode_gzip(s): return gzip.decompress(base64.b64decode(s.encode())).decode()

def main():
    p = argparse.ArgumentParser(description="Advanced Cybersecurity Encoder/Decoder CLI for Web App Pentesting")
    p.add_argument('-f','--file', help="Input file")
    p.add_argument('-d','--decode', action='store_true', help="Decode mode")
    p.add_argument('--shift', type=int, default=3, help="Caesar shift (default=3)")
    p.add_argument('--xor-key', type=int, help="XOR key (0‑255)")
    p.add_argument('--vigenere-key', type=str, help="Vigenere cipher key")
    p.add_argument('--funny-function', type=str, help="Function name for funny Unicode (e.g., 'eval', 'exec', 'system')")
    p.add_argument('--zalgo-craziness', type=int, default=3, choices=range(1, 11), help="Zalgo craziness level (1-10, default=3)")
    p.add_argument('--zalgo-above', action='store_true', help="Add zalgo marks above characters")
    p.add_argument('--zalgo-below', action='store_true', help="Add zalgo marks below characters") 
    p.add_argument('--zalgo-overlay', action='store_true', help="Add overlay zalgo marks")
    p.add_argument('--examples', action='store_true', help="Show usage examples and exit")

    # Check for examples before requiring other args
    if '--examples' in sys.argv:
        show_examples()

    group = p.add_mutually_exclusive_group(required=True)
    
    # Original encodings
    for name in ("urlencode","xml","base85","base64","b64url","html",
                 "ascii-hex","hex","octal","binary","gzip",
                 "rot13","caesar","xor","md5","sha1","sha256"):
        group.add_argument(f'--{name}', action='store_true')
    
    # Advanced Web App Pentesting Encodings
    for name in ("double-url","triple-url","unicode","unicode-mixed","unicode-overlong",
                 "html-named","html-hex","html-decimal","js-unicode","js-hex","json",
                 "base32","base58","ldap","css","sql-char","sql-hex","powershell",
                 "mixed-case","utf7","utf16","morse","atbash","vigenere","rot47",
                 "php-serialize","pickle-hex","backslash","windows1252",
                 "math-unicode","math-mono","fullwidth","invisible",
                 "funny-chr","funny-eval","funny-simple","funny-import","funny-getattr","funny-italic"):
        group.add_argument(f'--{name}', action='store_true')
    
    # New encodings
    for name in ("case-alternating","case-random","case-vowel-upper","case-consonant-upper",
                 "unicode-zalgo","unicode-homograph","emoji","utf7-plus",
                 "utf8-overlong-manual","utf16-mixed-endian","invisible-separator",
                 "invisible-bidirectional","html-entity-mixed","xml-cdata",
                 "sql-comment-obfuscate","sql-concat-obfuscate","js-string-split",
                 "js-fromcharcode","js-template-literal","php-chr-concat",
                 "php-hex","php-base64-encode-custom","math-unicode-script",
                 "math-unicode-fraktur","math-unicode-double-struck","funny-any",
                 "unicode-zalgo-crazy","unicode-confusables","unicode-nfc","unicode-nfd",
                 "unicode-nfkc","unicode-nfkd","utf8-null-byte","utf8-bom","utf32",
                 "base36","base62","bzip2","lzma","chain-b64-url-double",
                 "polyglot-js-php","polyglot-html-js","format-string","printf-format",
                 "binary-msb","binary-lsb","null-byte-terminate","null-byte-prefix",
                 "null-byte-middle","null-byte-scatter","null-byte-hex","null-byte-backslash",
                 "null-byte-unicode","terminal-escape","terminal-cursor","terminal-control-chars",
                 "path-traversal","file-extension-null","file-double-extension","file-case-bypass",
                 "control-char-hex","control-char-octal","control-char-caret","dos-device-names",
                 "windows-alternate-stream","windows-short-name","crlf-injection",
                 "http-parameter-pollution","url-fragment","punycode","format-string-printf",
                 "format-string-positional","format-string-width","unicode-ltr-override",
                 "unicode-rtl-override","unicode-ltr-embed","unicode-rtl-embed",
                 "unicode-line-separator","unicode-paragraph-separator","unicode-soft-hyphen",
                 "unicode-ideographic-description","unicode-variation-selectors","unicode-tag-characters",
                 "unicode-private-use","unicode-surrogate-pairs","unicode-canonical-confusion",
                 "unicode-bom-injection","unicode-grapheme-cluster","unicode-script-mixing",
                 "unicode-format-characters","html-hex-leading-zeros","html-decimal-leading-zeros",
                 "xml-hex-leading-zeros","xml-decimal-leading-zeros","unicode-escape-leading-zeros",
                 "unicode-traditional-leading-zeros","js-unicode-leading-zeros","hex-escape-leading-zeros",
                 "html-unicode-double","unicode-html-double","url-html-double","html-url-double",
                 "triple-url-html-unicode","sql-char-hex-mixed","sql-unhex","sql-hex-literal",
                 "sql-binary","sql-ascii","js-fromcharcode-split","js-eval-fromcharcode",
                 "js-unescape","php-chr-hex-mixed","php-pack","php-hex2bin","powershell-char-array",
                 "powershell-format","bash-dollar","bash-printf","xml-cdata-advanced",
                 "xml-processing-instruction","base64-chunked","base64-atob","case-unicode-mixed"):
        group.add_argument(f'--{name}', action='store_true')
    
    args = p.parse_args()
    
    # Handle examples first
    if args.examples:
        show_examples()
    
    text = read_input(args.file).strip()

    try:
        # Original encodings
        if args.urlencode:
            print(decode_url(text) if args.decode else urlencode_ascii(text))
        elif args.xml:
            print(decode_xml(text) if args.decode else xml_encode(text))
        elif args.base85:
            print(decode_base85(text) if args.decode else encode_base85(text))
        elif args.base64:
            print(decode_base64(text) if args.decode else encode_base64(text))
        elif args.b64url:
            print(decode_b64_url(text) if args.decode else encode_b64_url(text))
        elif args.html:
            print(html.unescape(text) if args.decode else html.escape(text))
        elif args.ascii_hex:
            print(decode_ascii_hex(text) if args.decode else encode_ascii_hex(text))
        elif args.hex:
            print(decode_hex(text) if args.decode else encode_hex(text))
        elif args.octal:
            print(decode_octal(text) if args.decode else encode_octal(text))
        elif args.binary:
            print(decode_binary(text) if args.decode else encode_binary(text))
        elif args.gzip:
            print(decode_gzip(text) if args.decode else encode_gzip(text))
        elif args.rot13:
            print(rot13(text))
        elif args.caesar:
            if args.decode: args.shift = -args.shift
            print(caesar(text, args.shift))
        elif args.xor:
            if args.xor_key is None:
                sys.exit("Error: --xor-key required for XOR")
            print(xor_cipher(text, args.xor_key))
        elif args.md5:
            print(hash_md5(text))
        elif args.sha1:
            print(hash_sha1(text))
        elif args.sha256:
            print(hash_sha256(text))
            
        # Advanced Web App Pentesting Encodings
        elif args.double_url:
            print(decode_double_url(text) if args.decode else double_urlencode(text))
        elif args.triple_url:
            print(decode_triple_url(text) if args.decode else triple_urlencode(text))
        elif args.unicode:
            print(decode_unicode_escape(text) if args.decode else unicode_escape(text))
        elif args.unicode_mixed:
            print(decode_unicode_escape(text) if args.decode else unicode_escape_mixed(text))
        elif args.unicode_overlong:
            print(decode_double_url(text) if args.decode else unicode_overlong_utf8(text))
        elif args.html_named:
            print(html.unescape(text) if args.decode else html_named_entities(text))
        elif args.html_hex:
            print(html.unescape(text) if args.decode else html_hex_entities(text))
        elif args.html_decimal:
            print(html.unescape(text) if args.decode else html_decimal_entities(text))
        elif args.js_unicode:
            print(decode_unicode_escape(text) if args.decode else js_unicode_escape(text))
        elif args.js_hex:
            print(decode_unicode_escape(text) if args.decode else js_hex_escape(text))
        elif args.json:
            if args.decode:
                print(json.loads(f'"{text}"'))
            else:
                print(json_escape(text))
        elif args.base32:
            print(decode_base32(text) if args.decode else encode_base32(text))
        elif args.base58:
            print(decode_base58(text) if args.decode else encode_base58(text))
        elif args.ldap:
            print(ldap_escape(text))  # LDAP escaping is typically one-way
        elif args.css:
            print(css_escape(text))
        elif args.sql_char:
            print(sql_char_encoding(text))
        elif args.sql_hex:
            print(sql_hex_encoding(text))
        elif args.powershell:
            print(powershell_escape(text))
        elif args.mixed_case:
            print(mixed_case(text))
        elif args.utf7:
            print(utf7_decode(text) if args.decode else utf7_encode(text))
        elif args.utf16:
            print(utf16_decode(text) if args.decode else utf16_encode(text))
        elif args.morse:
            print(morse_encode(text))  # Morse is typically one-way in this context
        elif args.atbash:
            print(atbash_cipher(text))  # Atbash is symmetric
        elif args.vigenere:
            if args.vigenere_key is None:
                sys.exit("Error: --vigenere-key required for Vigenere cipher")
            print(vigenere_decode(text, args.vigenere_key) if args.decode else vigenere_encode(text, args.vigenere_key))
        elif args.rot47:
            print(rot47(text))  # ROT47 is symmetric
        elif args.php_serialize:
            print(php_serialize(text))
        elif args.pickle_hex:
            print(python_pickle_hex(text))
        elif args.backslash:
            print(backslash_escape(text))
        elif args.windows1252:
            print(windows1252_decode(text) if args.decode else windows1252_encode(text))
        elif args.math_unicode:
            print(math_unicode_decode(text) if args.decode else math_unicode_encode(text))
        elif args.math_mono:
            print(math_unicode_decode(text) if args.decode else math_unicode_monospace_encode(text))
        elif args.fullwidth:
            print(fullwidth_decode(text) if args.decode else fullwidth_encode(text))
        elif args.invisible:
            print(invisible_unicode_decode(text) if args.decode else invisible_unicode_encode(text))
        elif args.funny_chr:
            print(funny_unicode_chr_encode(text))  # Python code injection - no decode needed
        elif args.funny_eval:
            print(funny_unicode_eval_encode(text))
        elif args.funny_simple:
            print(funny_unicode_simple_encode(text))
        elif args.funny_import:
            print(python_unicode_import_encode(text))
        elif args.funny_getattr:
            print(python_unicode_getattr_encode(text))
        elif args.funny_italic:
            print(funny_unicode_italic_encode(text))
            
        # New encodings
        elif args.case_alternating:
            print(case_alternating_encode(text))
        elif args.case_random:
            print(case_random_encode(text))
        elif args.case_vowel_upper:
            print(case_vowel_upper_encode(text))
        elif args.case_consonant_upper:
            print(case_consonant_upper_encode(text))
        elif args.unicode_zalgo:
            print(unicode_zalgo_encode(text))
        elif args.unicode_homograph:
            print(unicode_homograph_encode(text))
        elif args.emoji:
            print(emoji_encode(text))
        elif args.utf7_plus:
            print(utf7_plus_encode(text))
        elif args.utf8_overlong_manual:
            print(utf8_overlong_manual(text))
        elif args.utf16_mixed_endian:
            print(utf16_mixed_endian(text))
        elif args.invisible_separator:
            print(invisible_separator_encode(text))
        elif args.invisible_bidirectional:
            print(invisible_bidirectional_encode(text))
        elif args.html_entity_mixed:
            print(html_entity_mixed_encode(text))
        elif args.xml_cdata:
            print(xml_cdata_encode(text))
        elif args.sql_comment_obfuscate:
            print(sql_comment_obfuscate(text))
        elif args.sql_concat_obfuscate:
            print(sql_concat_obfuscate(text))
        elif args.js_string_split:
            print(js_string_split_encode(text))
        elif args.js_fromcharcode:
            print(js_fromcharcode_encode(text))
        elif args.js_template_literal:
            print(js_template_literal_encode(text))
        elif args.php_chr_concat:
            print(php_chr_concat_encode(text))
        elif args.php_hex:
            print(php_hex_encode(text))
        elif args.php_base64_encode_custom:
            print(php_base64_encode_custom(text))
        elif args.math_unicode_script:
            print(math_unicode_script_encode(text))
        elif args.math_unicode_fraktur:
            print(math_unicode_fraktur_encode(text))
        elif args.math_unicode_double_struck:
            print(math_unicode_double_struck_encode(text))
        elif args.funny_any:
            function_name = args.funny_function if args.funny_function else "exec"
            print(funny_unicode_any_function(text, function_name))
        
        # Advanced new encoders
        elif args.unicode_zalgo_crazy:
            # Set defaults if flags not explicitly set
            above = args.zalgo_above or not (args.zalgo_below or args.zalgo_overlay)
            below = args.zalgo_below or not (args.zalgo_above or args.zalgo_overlay)
            overlay = args.zalgo_overlay or not (args.zalgo_above or args.zalgo_below)
            print(unicode_zalgo_crazy_encode(text, args.zalgo_craziness, above, below, overlay))
        elif args.unicode_confusables:
            print(unicode_confusables_encode(text))
        elif args.unicode_nfc:
            print(unicode_normalization_nfc(text))
        elif args.unicode_nfd:
            print(unicode_normalization_nfd(text))
        elif args.unicode_nfkc:
            print(unicode_normalization_nfkc(text))
        elif args.unicode_nfkd:
            print(unicode_normalization_nfkd(text))
        elif args.utf8_null_byte:
            print(utf8_null_byte_encode(text))
        elif args.utf8_bom:
            print(utf8_bom_encode(text))
        elif args.utf32:
            print(utf32_decode(text) if args.decode else utf32_encode(text))
        elif args.base36:
            print(base36_decode(text) if args.decode else base36_encode(text))
        elif args.base62:
            print(base62_decode(text) if args.decode else base62_encode(text))
        elif args.bzip2:
            print(bzip2_decode(text) if args.decode else bzip2_encode(text))
        elif args.lzma:
            print(lzma_decode(text) if args.decode else lzma_encode(text))
        elif args.chain_b64_url_double:
            print(chain_decode_b64_url_double(text) if args.decode else chain_encode_b64_url_double(text))
        elif args.polyglot_js_php:
            print(polyglot_js_php_encode(text))
        elif args.polyglot_html_js:
            print(polyglot_html_js_encode(text))
        elif args.format_string:
            print(format_string_encode(text))
        elif args.printf_format:
            print(printf_format_encode(text))
        elif args.binary_msb:
            print(binary_msb_decode(text) if args.decode else binary_msb_encode(text))
        elif args.binary_lsb:
            print(binary_lsb_decode(text) if args.decode else binary_lsb_encode(text))
        
        # Null Byte Injection Techniques
        elif args.null_byte_terminate:
            print(null_byte_terminate(text))
        elif args.null_byte_prefix:
            print(null_byte_prefix(text))
        elif args.null_byte_middle:
            print(null_byte_middle(text))
        elif args.null_byte_scatter:
            print(null_byte_scatter(text))
        elif args.null_byte_hex:
            print(null_byte_hex_encode(text))
        elif args.null_byte_backslash:
            print(null_byte_backslash_encode(text))
        elif args.null_byte_unicode:
            print(null_byte_unicode_encode(text))
        
        # Terminal Escape Sequences
        elif args.terminal_escape:
            print(terminal_escape_decode(text) if args.decode else terminal_escape_encode(text))
        elif args.terminal_cursor:
            print(terminal_cursor_encode(text))
        elif args.terminal_control_chars:
            print(terminal_control_chars_encode(text))
        
        # File Path Injection
        elif args.path_traversal:
            print(path_traversal_encode(text))
        elif args.file_extension_null:
            print(file_extension_null_encode(text))
        elif args.file_double_extension:
            print(file_double_extension_encode(text))
        elif args.file_case_bypass:
            print(file_case_bypass_encode(text))
        
        # Control Character Encodings
        elif args.control_char_hex:
            print(control_char_hex_encode(text))
        elif args.control_char_octal:
            print(control_char_octal_encode(text))
        elif args.control_char_caret:
            print(control_char_caret_encode(text))
        
        # Windows/DOS Bypasses
        elif args.dos_device_names:
            print(dos_device_names_encode(text))
        elif args.windows_alternate_stream:
            print(windows_alternate_stream_encode(text))
        elif args.windows_short_name:
            print(windows_short_name_encode(text))
        
        # Network Protocol Bypasses
        elif args.crlf_injection:
            print(crlf_injection_encode(text))
        elif args.http_parameter_pollution:
            print(http_parameter_pollution(text))
        elif args.url_fragment:
            print(url_fragment_encode(text))
        elif args.punycode:
            print(punycode_decode(text) if args.decode else punycode_encode(text))
        
        # Format String Injection
        elif args.format_string_printf:
            print(format_string_printf(text))
        elif args.format_string_positional:
            print(format_string_positional(text))
        elif args.format_string_width:
            print(format_string_width(text))
        
        # Unicode Bidirectional Overrides
        elif args.unicode_ltr_override:
            print(unicode_ltr_override(text))
        elif args.unicode_rtl_override:
            print(unicode_rtl_override(text))
        elif args.unicode_ltr_embed:
            print(unicode_ltr_embed(text))
        elif args.unicode_rtl_embed:
            print(unicode_rtl_embed(text))
        
        # Advanced Unicode Attacks
        elif args.unicode_line_separator:
            print(unicode_line_separator_inject(text))
        elif args.unicode_paragraph_separator:
            print(unicode_paragraph_separator_inject(text))
        elif args.unicode_soft_hyphen:
            print(unicode_soft_hyphen_inject(text))
        elif args.unicode_ideographic_description:
            print(unicode_ideographic_description(text))
        elif args.unicode_variation_selectors:
            print(unicode_variation_selectors(text))
        elif args.unicode_tag_characters:
            print(unicode_tag_characters(text))
        elif args.unicode_private_use:
            print(unicode_private_use_decode(text) if args.decode else unicode_private_use_encode(text))
        elif args.unicode_surrogate_pairs:
            print(unicode_surrogate_pairs_encode(text))
        elif args.unicode_canonical_confusion:
            print(unicode_canonical_confusion(text))
        elif args.unicode_bom_injection:
            print(unicode_bom_injection(text))
        elif args.unicode_grapheme_cluster:
            print(unicode_grapheme_cluster_attack(text))
        elif args.unicode_script_mixing:
            print(unicode_script_mixing_attack(text))
        elif args.unicode_format_characters:
            print(unicode_format_characters_inject(text))
        
        # Advanced Obfuscation Techniques (Leading Zeros)
        elif args.html_hex_leading_zeros:
            print(html_hex_entities_leading_zeros(text))
        elif args.html_decimal_leading_zeros:
            print(html_decimal_entities_leading_zeros(text))
        elif args.xml_hex_leading_zeros:
            print(xml_hex_entities_leading_zeros(text))
        elif args.xml_decimal_leading_zeros:
            print(xml_decimal_entities_leading_zeros(text))
        elif args.unicode_escape_leading_zeros:
            print(unicode_escape_leading_zeros(text))
        elif args.unicode_traditional_leading_zeros:
            print(unicode_escape_traditional_leading_zeros(text))
        elif args.js_unicode_leading_zeros:
            print(js_unicode_escape_leading_zeros(text))
        elif args.hex_escape_leading_zeros:
            print(hex_escape_leading_zeros(text))
        
        # Multiple Encoding Combinations
        elif args.html_unicode_double:
            print(html_unicode_double_encode(text))
        elif args.unicode_html_double:
            print(unicode_html_double_encode(text))
        elif args.url_html_double:
            print(url_html_double_encode(text))
        elif args.html_url_double:
            print(html_url_double_encode(text))
        elif args.triple_url_html_unicode:
            print(triple_encode_url_html_unicode(text))
        
        # Advanced SQL Obfuscation
        elif args.sql_char_hex_mixed:
            print(sql_char_hex_mixed(text))
        elif args.sql_unhex:
            print(sql_unhex_encode(text))
        elif args.sql_hex_literal:
            print(sql_hex_literal(text))
        elif args.sql_binary:
            print(sql_binary_encode(text))
        elif args.sql_ascii:
            print(sql_ascii_encode(text))
        
        # JavaScript Context Specific
        elif args.js_fromcharcode_split:
            print(js_string_fromcharcode_split(text))
        elif args.js_eval_fromcharcode:
            print(js_eval_fromcharcode(text))
        elif args.js_unescape:
            print(js_unescape_encode(text))
        
        # PHP Context Specific
        elif args.php_chr_hex_mixed:
            print(php_chr_hex_mixed(text))
        elif args.php_pack:
            print(php_pack_encode(text))
        elif args.php_hex2bin:
            print(php_hex2bin_encode(text))
        
        # PowerShell Specific
        elif args.powershell_char_array:
            print(powershell_char_array(text))
        elif args.powershell_format:
            print(powershell_format_operator(text))
        
        # Linux/Bash Specific
        elif args.bash_dollar:
            print(bash_dollar_escape(text))
        elif args.bash_printf:
            print(bash_printf_escape(text))
        
        # Advanced XML Techniques
        elif args.xml_cdata_advanced:
            print(xml_cdata_escape(text))
        elif args.xml_processing_instruction:
            print(xml_processing_instruction(text))
        
        # Advanced Base64 Variations
        elif args.base64_chunked:
            print(base64_chunked_encode(text))
        elif args.base64_atob:
            print(base64_with_decode_function(text))
        
        # Advanced Case Obfuscation
        elif args.case_unicode_mixed:
            print(case_unicode_mixed(text))
            
    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()