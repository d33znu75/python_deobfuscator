import re
import ast
import sys
import gzip
import io
import base64

# class PythonDeobfuscator:
#     def __init__(self, deob1=None):
#         self.deob1 = deob1  # Input data passed during initialization
#         self.code = None
#         self.simplified_code = None
    
#     def load_code(self):
#         """Load code from the deob1 variable"""
#         if self.deob1:
#             self.code = self.deob1
#         else:
#             print("No input data provided in deob1.")
#             return False
#         return True
    
#     def simplify_chr_expressions(self):
#         """Replace complex chr() expressions with their actual characters"""
#         if not self.code:
#             return False
        
#         # Handle chr() with arithmetic operations inside
#         def replace_chr_math(match):
#             expr = match.group(1)
#             try:
#                 # Safely evaluate the expression
#                 value = ast.literal_eval(expr)
#                 return f"'{chr(value)}'"
#             except:
#                 # If evaluation fails, return the original
#                 return f"chr({expr})"
        
#         # First simple chr() calls
#         self.code = re.sub(r'chr\(([0-9]+)\)', lambda m: f"'{chr(int(m.group(1)))}'", self.code)
        
#         # Binary and octal representations
#         self.code = re.sub(r'chr\(0b([01]+)\)', lambda m: f"'{chr(int(m.group(1), 2))}'", self.code)
#         self.code = re.sub(r'chr\(0o([0-7]+)\)', lambda m: f"'{chr(int(m.group(1), 8))}'", self.code)
        
#         # Handle more complex expressions inside chr()
#         pattern = r'chr\(([^)]+)\)'
#         while re.search(pattern, self.code):
#             self.code = re.sub(pattern, replace_chr_math, self.code)
        
#         return True
    
#     def simplify_string_concatenations(self):
#         """Simplify string concatenations like 'a' + 'b' + 'c' to 'abc'"""
#         if not self.code:
#             return False
        
#         # Find patterns of string concatenation
#         pattern = r'(\'[^\']*\'|\"[^\"]*\")\s*\+\s*(\'[^\']*\'|\"[^\"]*\")'
        
#         while re.search(pattern, self.code):
#             self.code = re.sub(pattern, 
#                               lambda m: f"'{ast.literal_eval(m.group(1)) + ast.literal_eval(m.group(2))}'", 
#                               self.code)
        
#         return True
    
#     def simplify_escape_sequences(self):
#         """Convert escape sequences in strings to their actual characters"""
#         if not self.code:
#             return False
        
#         # Find strings with escape sequences but exclude binary strings (b'...')
#         pattern = r'(?<!b)(\'[^\']*\\x[0-9a-fA-F]{2}[^\']*\'|\"[^\"]*\\x[0-9a-fA-F]{2}[^\"]*\")'
        
#         while re.search(pattern, self.code):
#             self.code = re.sub(pattern, 
#                               lambda m: f"'{ast.literal_eval(m.group(1))}'", 
#                               self.code)
        
#         return True
    
#     def simplify_int_conversions(self):
#         """Simplify int() conversions with different bases"""
#         if not self.code:
#             return False
        
#         # Match patterns like int('123', 8) or int('101', 2)
#         pattern = r'int\(\s*(\'[^\']*\'|\"[^\"]*\")\s*,\s*([0-9]+)\s*\)'
        
#         self.code = re.sub(pattern, 
#                           lambda m: str(int(ast.literal_eval(m.group(1)), int(m.group(2)))), 
#                           self.code)
        
#         return True
    
#     def simplify_arithmetic(self):
#         """Simplify arithmetic operations like 1210 - 1162"""
#         if not self.code:
#             return False
        
#         # Match arithmetic operations on numbers
#         pattern = r'([0-9]+)\s*(\+|\-|\*|\/)\s*([0-9]+)'
        
#         def evaluate_arithmetic(match):
#             a = int(match.group(1))
#             op = match.group(2)
#             b = int(match.group(3))
            
#             if op == '+':
#                 return str(a + b)
#             elif op == '-':
#                 return str(a - b)
#             elif op == '*':
#                 return str(a * b)
#             elif op == '/':
#                 return str(a / b)
            
#             return match.group(0)
        
#         while re.search(pattern, self.code):
#             self.code = re.sub(pattern, evaluate_arithmetic, self.code)
        
#         return True
    
#     def simplify_number_formats(self):
#         """Convert binary and octal representations to decimal"""
#         if not self.code:
#             return False
        
#         # Binary numbers (0b101)
#         self.code = re.sub(r'0b([01]+)', lambda m: str(int(m.group(1), 2)), self.code)
        
#         # Octal numbers (0o123)
#         self.code = re.sub(r'0o([0-7]+)', lambda m: str(int(m.group(1), 8)), self.code)
        
#         return True
    
#     def deobfuscate(self):
#         """Run all deobfuscation methods"""
#         if not self.load_code():
#             return None
        
#         # apply deobfuscation techniques multiple times, might reveal more patterns
#         for _ in range(3):
#             self.simplify_number_formats()
#             self.simplify_arithmetic()
#             self.simplify_chr_expressions()
#             self.simplify_escape_sequences()
#             self.simplify_string_concatenations()
#             self.simplify_int_conversions()
        
#         self.simplified_code = self.code
#         return self.simplified_code


# ###### DEOBFUSCATION FUNCTION ######

import re
import base64

def deobfuscate_xor_cipher(data):
    """Deobfuscate the XOR cipher used in the obfuscated code."""
    # Initialize default values for variables
    decode_func_name = "unknown_decoder"
    xor_func_name = "unknown_xor"
    func_name = "unknown_function"
    func_params = "params"
    context_manager = "unknown"
    file_operation = "unknown"
    binary_data = []
    
    # Parse the variable assignments at the beginning
    if '=' in data:
        vars_str = data.split('=', 1)[0]
        variables = vars_str.strip().split(',')
        
        # Parse the built-ins list at the end of the assignment
        builtins_str = data.split('=', 1)[1]
        builtins_list = builtins_str.strip().split(',')
        
        # Create a dictionary mapping obfuscated variable names to built-ins
        var_mapping = {}
        for i, var in enumerate(variables):
            if i < len(builtins_list):
                var_mapping[var.strip()] = builtins_list[i].strip()
    else:
        var_mapping = {}
    
    # Extract the lambda function that decodes bytes
    lambda_match = re.search(r'(\w+)\s*=\s*lambda\s+\w+:\s+(\w+)\(\[([^]]+)\]\)', data)
    if lambda_match:
        decode_func_name = lambda_match.group(1)
        xor_func_name = lambda_match.group(2)
        
        # Extract the XOR key values
        xor_key_pattern = re.compile(r'\[([^]]+)\]\[(\w+)\s*%\s*([^]]+)\]')
        xor_match = xor_key_pattern.search(lambda_match.group(3))
        if xor_match:
            xor_key = []
            key_values = re.findall(r'_eh_2TkiNTgJ\(([^)]+)\)', xor_match.group(1))
            for value in key_values:
                # This would need parsing of the complex expressions inside
                # For simplicity, we're just identifying the pattern
                xor_key.append(value)
    
    # Extract encoded binary data
    pattern = r'DUbPzUpjXhxz\(b\'([^\']+)\'\)'
    for match in re.finditer(pattern, data):
        hex_str = ''
        for byte in match.group(1):
            hex_str += f'\\x{ord(byte):02x}'
        binary_data.append(f"b'{hex_str}'")
    
    # Recreate the function that would call the decoded code
    func_match = re.search(r'def\s+(\w+)\(([^)]+)\):\s*try:', data)
    if func_match:
        func_name = func_match.group(1)
        func_params = func_match.group(2)
    
    # Identify the with statement and the file operations
    with_match = re.search(r'with\s+(\w+)\(([^)]+)\)', data)
    if with_match:
        context_manager = with_match.group(1)
        file_operation = with_match.group(2)
    
    # Reconstruct the decoded operations
    deobfuscated = f"""
# Deobfuscated code
# The original code performs these operations:

# 1. Defines a lambda function that decodes obfuscated data using XOR
{decode_func_name} = lambda data: xor_decode(data, key)

# 2. Defines a function that uses the decoded data
def {func_name}({func_params}):
    # Executes the decoded data with parameters

# 3. Opens a file or connection and writes decoded data to it
with open("output_file", "wb") as f:
    f.write(decoded_data)

# 4. Executes some decoded command

# Encoded binary data found in the code:
{', '.join(binary_data) if binary_data else "No binary data found"}
"""
    
    return deobfuscated

# Example usage
def d2(data):
    deobfuscated_code = deobfuscate_xor_cipher(data)
    return deobfuscated_code

######################################

def deobfuscate_first(data):
    match = re.search(r'_=exec;_\(\'(.*?)\'\)', data)
    if not match:
        return "No match found for '_=exec;_('"
    hexed = match.group(1)
    hexed = hexed.replace('\\x', '')
    unhex = bytes.fromhex(hexed).decode('utf-8')
    match = re.search(r'exec;__\(___\(_\(b\'(.*?)\'\)', unhex)
    if not match:
        return "No match found for 'exec;__\(___\(_\(b\''"
    endatad = match.group(1)
    endatad = base64.b85decode(endatad).decode('utf-8')
    match = re.search(r'_=\[(.*?)\];', endatad)
    list1 = match.group(1).split(', ')
    if not list1:
        return "No base64 list found"
    match = re.search(r'for _______,______ in enumerate\(\[(.*?)\]\):', endatad)
    if not match:
        return "No enumerate list found"
    list2 = match.group(1).split(', ')
    list1_len = len(list1)
    for i, c in enumerate(list2):
        list2[i] = chr(int(c) ^ int(list1[i % list1_len]))
    out1 = ''.join(list2)
    match = re.search(r';_=exec;_\(__\(b\'(.*?)\'\)', out1)
    if not match:
        return "No match found for ';_=exec;_\(__\(b\''"
    compressed_b64 = match.group(1)
    exec_globals = {}
    exec(f"match = b'{compressed_b64}'", exec_globals)
    compressed_data = exec_globals.get("match")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as f:
        decompressed_data = f.read()
    decompressed_data = decompressed_data.decode('utf-8')
    return decompressed_data


def decode_pipobfuscator(data):
    input = data

    # Get the deobfuscated data from deobfuscate_first
    try:
        deob1 = deobfuscate_first(input)
        deob2 = d2(deob1)
        return deob1
    except Exception as e:
        return f"Deobfuscation failed: {str(e)}"

# def decode_pipobfuscator(data):
    
#     input = data

#     # Get the deobfuscated data from deobfuscate_first
#     deob1 = deobfuscate_first(input)
#     deob2 = d2(deob1)
    
#     # Pass the deob1 data to the PythonDeobfuscator class
#     # deobfuscator = PythonDeobfuscator(deob1=deob1)
#     # deobfuscated = deobfuscator.deobfuscate()
#     # return deobfuscated
#     return deob2
