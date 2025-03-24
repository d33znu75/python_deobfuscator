from flask import Flask, request, render_template # type: ignore
from modules import decode_lambda_hex, decode_lambda_base64, decode_pipobfuscator, decode_malwarekid
import re

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def auto_detect(data):
    if not data:
        return "No input data."
    match = re.search(r"fromhex\('([0-9a-fA-F]+)'\.replace", data)
    if match:
        return decode_lambda_hex(data)
    match = re.search(r"b'([A-Za-z0-9+/=]+)'", data)
    if match:
        return decode_lambda_base64(data)
    match = re.search("FOLLOW_MALWAREKID", data)
    if match:
        return decode_malwarekid(data)
    match = re.search(r"exec\(\"\".join\(chr\(ord\(c\) \^ ", data)
    if match:
        return decode_malwarekid(data)
    match = re.search(r"_=exec;_\(\'\\x", data)
    if match:
        return decode_pipobfuscator(data)
    
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
    elif option == 'option3':
        result = decode_malwarekid(input_text)
    elif option == 'option4':
        result = decode_pipobfuscator(input_text)
    else:
        result = "No valid option selected."

    return result

if __name__ == '__main__':
    #app.run(debug=False)
    app.run(host='0.0.0.0', port=5000)