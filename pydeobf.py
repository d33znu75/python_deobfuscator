from flask import Flask, request, render_template # type: ignore
import base64
import zlib
import re
import binascii

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def decode_lambda_base64(data):
    if not data:
        return "No input data."
    while True:
        match = re.search(r"b'([A-Za-z0-9+/=]+)'", data)
        if not match:
            break
        encoded_data = match.group(1)[::-1]
        try:
            decoded = base64.b64decode(encoded_data)
            try:
                decompressed = zlib.decompress(decoded)
                data = decompressed.decode()
            except zlib.error:
                return "No zlib compression detected."
        except Exception as e:
            return f"Decoding failed: {e}"
    return data

name_mappings = {
    '___': 'create_type',
    '_0_': 'to_str',
    '_____': 'to_dict',
    '_0': 'get_arg_count',
    '________': 'none_value',
    '__0': 'get_arg_count_alias',
    '______': 'dynamic_type',
    '____': 'empty_list',
    '_______________': 'hex_func',
    '______': 'pow_func',
    '__________': 'complex_expr',
    '___________________': 'ge_method',
    '_______': 'create_instance',
    '_____________________': 'get_attr',
    '______________________': 'get_globals',
    '________': 'some_method',
    '________________': 'empty_list',
    '__________________': 'dir_method',
    '_________': 'class_method',
    '_____________': 'ord_method',
    '____': 'complex_expr_2',
    '___________': 'create_instance_2',
    '__': 'empty_dict',
    '______________': 'eq_method',
    '_______________________': 'name_method',
    '________________________': 'iter_method',
    '____________________': 'complex_method',
    '_________________________': 'file_method',
    '_________________': 'float_method',
    '_____': 'str_method',
    '____________': 'complex_expr_3',
}


def deobf_hex_1(data):
    obfuscated_code = data
    for obfuscated_name, meaningful_name in name_mappings.items():
        obfuscated_code = re.sub(r'\b' + re.escape(obfuscated_name) + r'\b', meaningful_name, obfuscated_code)
    return obfuscated_code

def decode_lambda_hex(data):
    while True:
        if not data:
            return "No input data."
        match = re.search(r"fromhex\('([0-9a-fA-F]+)'\.replace", data) # Extract the hex encoded string between ('')
        if not match:
            break
        encoded_data = match.group(1)
        try:
            decoded = binascii.unhexlify(encoded_data)
            # print("Decoded data:", decoded)
            try:
                decompressed = zlib.decompress(decoded)
                data = decompressed.decode()
            except zlib.error:
                return "No zlib compression detected."
        except Exception as e:
            return f"Decoding failed: {e}"
    # return deobf_hex_1(data)
    return data

def auto_detect(data):
    if not data:
        return "No input data."
    match = re.search(r"fromhex\('([0-9a-fA-F]+)'\.replace", data)
    if match:
        return decode_lambda_hex(data)
    match = re.search(r"b'([A-Za-z0-9+/=]+)'", data)
    if match:
        return decode_lambda_base64(data)
    return "Obfuscation method not supported."

@app.route('/deobf', methods=['POST'])
def deobf():
    input_text = request.form.get('input_text', '')
    option = request.form.get('option', '')

    if option == 'auto':
        return auto_detect(input_text)
    elif option == 'option1':
        result = decode_lambda_hex(input_text)
    elif option == 'option2':
        result = decode_lambda_base64(input_text)
    else:
        result = "No valid option selected."

    return result

if __name__ == '__main__':
    app.run(debug=False)