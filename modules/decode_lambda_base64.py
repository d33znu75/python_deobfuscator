import re
import base64
import zlib

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