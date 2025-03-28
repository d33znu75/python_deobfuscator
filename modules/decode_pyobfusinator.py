import re
import ast
from string import printable as b



def custom_exec(source, *args, **kwargs):
    return source


def decode_pyobfusinator(input_text):
    method = 0
    match = re.search(r"\.encode\(\);exec\(''.join\(chr\(", input_text)
    if match:
        final = "# Decoded from PyObfusinator with Compress method\n\n"
        method = 2
    if 'str(eval)' and '[]' and 'str' and 'eval' and '+all' in input_text:
        final = "# Decoded from PyObfusinator with Inflate method\n\n"
        method = 1
    if method == 2:
        tree = ast.parse(input_text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'exec':
                match = re.search(r"b=(.*?);exec", input_text).group(1)
                b = eval(match) # yeah i'm using eval, pls dont harm me :(
                match2 = re.search(r"exec\((.*)\)", input_text, re.DOTALL).group(1)
                result = eval(match2) # :3
                final += result
                return final
    if method == 1:
        exec = custom_exec
        tmp = input_text.split("exec")
        second_exec = 0
        for i in range(0, len(tmp)):
            if tmp[i].startswith("("):
                second_exec = i + 1
                break
        str2 = tmp[second_exec]
        final += eval(str2)
        return final
    if method == 0:
        return "# No input data."

    return "# Can't decode this PyObfusinator code."