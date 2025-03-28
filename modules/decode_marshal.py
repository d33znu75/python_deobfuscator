import base64
import marshal
import re
import dis
import zlib
import gzip
import lzma
import bz2
import types

def recursive_disassemble(code_obj):
    # disassembling the code object recursively to get all the instructions in the code object
    instructions = list(dis.get_instructions(code_obj))
    all_instructions = instructions.copy()
    for instr in instructions:
        if instr.opname == "LOAD_CONST" and isinstance(instr.argval, types.CodeType):
            nested_instructions = recursive_disassemble(instr.argval)
            all_instructions.extend(nested_instructions)
    return all_instructions

def zlib_loop(disassembled):
    while True:
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    decompressed = zlib.decompress(instr.argval)
                    unmarshalled = marshal.loads(decompressed)
                    disassembled = recursive_disassemble(unmarshalled)
                    break
                except Exception as e:
                    continue
        else:
            break
    return disassembled

def lzma_loop(disassembled):
    while True:
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    decompressed = lzma.decompress(instr.argval)
                    unmarshalled = marshal.loads(decompressed)
                    disassembled = recursive_disassemble(unmarshalled)
                    break
                except Exception as e:
                    continue
        else:
            break
    return disassembled

def base64_loop(disassembled):
    while True:
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    decoded = base64.b64decode(instr.argval)
                    unmarshalled = marshal.loads(decoded)
                    disassembled = recursive_disassemble(unmarshalled)
                    break
                except Exception as e:
                    continue
        else:
            break
    return disassembled

def bz2_loop(disassembled):
    while True:
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    decompressed = bz2.decompress(instr.argval)
                    unmarshalled = marshal.loads(decompressed)
                    disassembled = recursive_disassemble(unmarshalled)
                    break
                except Exception as e:
                    continue
        else:
            break
    return disassembled

def gzip_loop(disassembled):
    while True:
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    decompressed = gzip.decompress(instr.argval)
                    unmarshalled = marshal.loads(decompressed)
                    disassembled = recursive_disassemble(unmarshalled)
                except Exception as e:
                    continue
        else:
            break
    return disassembled

def get_second_method(disassembled):
    # get the next obfuscation method
    i = (len(disassembled))
    for instr in range(i):
        if disassembled[instr].argval == 'loads':
            j = instr
            break
    second_method = disassembled[j+2].argval
    return second_method



def zlib_loop(disassembled):
    while True:
        # Find the next zlib-compressed data
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    # Attempt to decompress the data
                    decompressed = zlib.decompress(instr.argval)
                    # Unmarshal the decompressed data
                    unmarshalled = marshal.loads(decompressed)
                    # Disassemble the new unmarshalled code
                    disassembled = list(dis.get_instructions(unmarshalled))
                    break  # Restart the loop with the new disassembled code
                except Exception as e:
                    # If decompression fails, continue searching
                    continue
        else:
            # If no zlib-compressed data is found, exit the loop
            break
    return disassembled

def lzma_loop(disassembled):
    while True:
        # Find the next lzma-compressed data
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    # Attempt to decompress the data
                    decompressed = lzma.decompress(instr.argval)
                    # Unmarshal the decompressed data
                    unmarshalled = marshal.loads(decompressed)
                    # Disassemble the new unmarshalled code
                    disassembled = list(dis.get_instructions(unmarshalled))
                    break  # Restart the loop with the new disassembled code
                except Exception as e:
                    # If decompression fails, continue searching
                    continue
        else:
            # If no lzma-compressed data is found, exit the loop
            break
    return disassembled

def base64_loop(disassembled):
    while True:
        # Find the next base64-encoded data
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    # Attempt to decode the base64 data
                    decoded = base64.b64decode(instr.argval)
                    # Unmarshal the decoded data
                    unmarshalled = marshal.loads(decoded)
                    # Disassemble the new unmarshalled code
                    disassembled = list(dis.get_instructions(unmarshalled))
                    break  # Restart the loop with the new disassembled code
                except Exception as e:
                    # If decoding fails, continue searching
                    continue
        else:
            # If no base64-encoded data is found, exit the loop
            break
    return disassembled

def bz2_loop(disassembled):
    while True:
        # Find the next bz2-compressed data
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    # Attempt to decompress the data
                    decompressed = bz2.decompress(instr.argval)
                    # Unmarshal the decompressed data
                    unmarshalled = marshal.loads(decompressed)
                    # Disassemble the new unmarshalled code
                    disassembled = list(dis.get_instructions(unmarshalled))
                    break  # Restart the loop with the new disassembled code
                except Exception as e:
                    # If decompression fails, continue searching
                    continue
        else:
            # If no bz2-compressed data is found, exit the loop
            break
    return disassembled

def gzip_loop(disassembled):
    while True:
        # Find the next gzip-compressed data
        for instr in disassembled:
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, bytes):
                try:
                    # Attempt to decompress the data
                    decompressed = gzip.decompress(instr.argval)
                    # Unmarshal the decompressed data
                    unmarshalled = marshal.loads(decompressed)
                    # Disassemble the new unmarshalled code
                    disassembled = list(dis.get_instructions(unmarshalled))
                    break  # Restart the loop with the new disassembled code
                except Exception as e:
                    # If decompression fails, continue searching
                    continue
        else:
            # If no gzip-compressed data is found, exit the loop
            break
    return disassembled

def get_second_method(disassembled):
    i = (len(disassembled))
    for instr in range(i):
        if disassembled[instr].argval == 'loads':
            j = instr
            break
    second_method = disassembled[j+2].argval
    return second_method

def decode_marshal(obfuscated):
    # base64
    match = re.search(r'binascii.a2b_base64\(b\'(.*?)\'\)', obfuscated)
    if match:
        encoded = match.group(1)
        encoded = encoded.encode('utf-8')
        encoded = base64.b64decode(encoded)
        unmarshalled = marshal.loads(encoded)
        disassembled = recursive_disassemble(unmarshalled)
    
    # lzma
    match = re.search(r'lzma.decompress\(b\'(.*?)\'\)\)\)\nexcept', obfuscated)
    if match:
        match = match.group(1)
        exec_globals = {}
        exec(f"match = b'{match}'", exec_globals)
        decompressed = lzma.decompress(exec_globals['match'])
        unmarshalled = marshal.loads(decompressed)
        disassembled = recursive_disassemble(unmarshalled)

    # bz2
    match = re.search(r'bz2.decompress\(b\'(.*?)\'\)\)\)\nexcept', obfuscated)
    if match:
        match = match.group(1)
        exec_globals = {}
        exec(f"match = b'{match}'", exec_globals)
        decompressed = bz2.decompress(exec_globals['match'])
        unmarshalled = marshal.loads(decompressed)
        disassembled = recursive_disassemble(unmarshalled)

    # gzip
    match = re.search(r'gzip.decompress\(b\'(.*?)\'\)\)\)\nexcept', obfuscated)
    if match:
        match = match.group(1)
        exec_globals = {}
        exec(f"match = b'{match}'", exec_globals)
        decompressed = gzip.decompress(exec_globals['match'])
        unmarshalled = marshal.loads(decompressed)
        disassembled = recursive_disassemble(unmarshalled)
    
    # zlib
    match = re.search(r'zlib.decompress\(b\'(.*?)\'\)\)\)\nexcept', obfuscated)
    if match:
        match = match.group(1)
        exec_globals = {}
        exec(f"match = b'{match}'", exec_globals)
        decompressed = zlib.decompress(exec_globals['match'])
        unmarshalled = marshal.loads(decompressed)
        disassembled = recursive_disassemble(unmarshalled)


    # loop to detect the compression method and decompress
    while True:
        try:
            second_method = get_second_method(disassembled)
        except:
            break
        if 'zlib' in second_method:
            disassembled = zlib_loop(disassembled)
        elif 'lzma' in second_method:
            disassembled = lzma_loop(disassembled)
        elif 'binascii' in second_method:
            disassembled = base64_loop(disassembled)
        elif 'bz2' in second_method:
            disassembled = bz2_loop(disassembled)
        elif 'gzip' in second_method:
            disassembled = gzip_loop(disassembled)
        else:
            break
    
    # return disassembled
    final = "# Decoded from Py-Fuscate\n"
    final += "# Generated Bytecode\n\n"
    for instr in disassembled:
        final += f"{instr.offset} {instr.opname} {instr.arg} ({instr.argrepr})\n"
    return final

