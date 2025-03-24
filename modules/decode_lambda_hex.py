# special credit to @over_on_top [github.com/0verp0wer] for the deobfuscation technique

import re
import ast
import sys
import zlib

from base64 import b85decode
from Crypto.Cipher import AES # type: ignore
from Crypto.Protocol.KDF import PBKDF2 # type: ignore


def deobfuscate(pyc, pye, httpspyobfuscatecom):
    def d(b, p):
        c = b85decode(b.encode('utf-8'))
        r = AES.new(PBKDF2(p, c[:16], dkLen=32, count=1000000), AES.MODE_GCM, nonce=c[16:32])
        return r.decrypt_and_verify(c[48:], c[32:48]).decode('utf-8')
    return(d(pyc + pye, httpspyobfuscatecom.replace('"', '')))

def decode_lambda_hex(data):
    file = data

    lines = file.split("\n")
    content_file = "\n".join(lines)

    if "pyobfuscate(" in content_file:
        for i, line in enumerate(lines):
            if line.strip().startswith("pyobfuscate("):
                pyobfuscate_value = lines[i]
                pyc_value = re.search(r"'pyc'\s*:\s*\"\"\"(.*?)\"\"\"", pyobfuscate_value, re.DOTALL).group(1)
                pye_value = re.search(r"'pye'\s*:\s*\"\"\"(.*?)\"\"\"", pyobfuscate_value, re.DOTALL).group(1)
                httpspyobfuscatecom = re.search(r"['\"]([lI]+)['\"]", pyobfuscate_value, re.DOTALL).group(0)
                content = deobfuscate(pyc_value, pye_value, httpspyobfuscatecom)
                break
    else:
        try:
            hex_string = re.findall(r"fromhex\('([0-9a-fA-F]+)'(?!\))", content_file)[0]
            layer_2 = zlib.decompress(bytes.fromhex(hex_string)).decode()
            obfuscated_code = ";".join(value for value in layer_2.split(";")[:-1])
            sys.setrecursionlimit(100000000)
            variable_code = re.findall(r'(\w+)\s*=\s*None', obfuscated_code)[0]
            
            # Create an execution environment with properly configured __builtins__
            # This ensures exec is available as both __builtins__['exec'] and __builtins__.exec
            import builtins
            exec_globals = {'__builtins__': builtins, '__': None}
            
            # Add exec directly to globals as a fallback
            exec_globals['exec'] = exec
            
            # Execute in the controlled environment
            exec(obfuscated_code, exec_globals)
            
            # Get the variable from the execution environment
            variable_value = exec_globals[variable_code]
            
            # Continue with the processing
            base85_code = ast.unparse(variable_value)
            base85_string = re.findall(r"\.b85decode\('([^']+)'\.encode\(\)\)", base85_code)[0]
            content = b85decode(base85_string.encode()).decode()
        except Exception as e:
            # Provide detailed error information for debugging
            return f"Decoding failed: {str(e)}\nError type: {type(e).__name__}"
    # Clean up the content by removing any sys.exit() lines
    if content:
        cleaned_lines = []
        for line in content.split('\n'):
            if "__import__('sys').exit()" not in line:
                cleaned_lines.append(line)
        content = '\n'.join(cleaned_lines)

    return content