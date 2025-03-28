# special credit to @over_on_top [github.com/0verp0wer] for the AES decryption algorithm

import re
import ast
import sys
import zlib
from base64 import b85decode
from Crypto.Cipher import AES # type: ignore
from Crypto.Protocol.KDF import PBKDF2 # type: ignore


def deobfuscate(pyc, pye, pyobf):
    def decrypt(b, p):
        c = b85decode(b.encode('utf-8'))
        r = AES.new(PBKDF2(p, c[:16], dkLen=32, count=1000000), AES.MODE_GCM, nonce=c[16:32])
        return r.decrypt_and_verify(c[48:], c[32:48]).decode('utf-8')
    return(decrypt(pyc + pye, pyobf.replace('"', '')))

def decode_lambda_hex(data):
    if not data:
        return "# No input data."
    file = data
    lines = file.split("\n")
    content_file = "\n".join(lines)
    try:
        hex_string = re.findall(r"fromhex\('([0-9a-fA-F]+)'(?!\))", content_file)[0]
        layer_2 = zlib.decompress(bytes.fromhex(hex_string)).decode()
        obfuscated_code = ";".join(value for value in layer_2.split(";")[:-1])
        sys.setrecursionlimit(100000000)
        variable_code = re.findall(r'(\w+)\s*=\s*None', obfuscated_code)[0]

        import builtins
        exec_globals = {'__builtins__': builtins, '__': None}
        exec_globals['exec'] = exec
        exec(obfuscated_code, exec_globals)
        variable_value = exec_globals[variable_code]

        base85_code = ast.unparse(variable_value)
        base85_string = re.findall(r"\.b85decode\('([^']+)'\.encode\(\)\)", base85_code)[0]
        content = b85decode(base85_string.encode()).decode()
    except Exception as e:
        err = "# PyObfuscate detected, but decoding failed.\n# Reason : " + str(e)
        return err
    if content:
        cleaned_lines = []
        for line in content.split('\n'):
            if "__import__('sys').exit()" not in line:
                cleaned_lines.append(line)
        content = '\n'.join(cleaned_lines)
    final = "# Decoded from PyObfuscate\n\n" + content
    return final