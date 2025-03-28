import re
import base64
import zlib

def decode_lambda_base64(data):
    if not data:
        return "# No input data."
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
                return "# Base64+Zlib detected, but decompression failed.\n# Reason : No zlib compression detected."
        except Exception as e:
            err = "# Base64+Zlib detected, but decoding failed.\n# Reason : " + str(e)
            return err
    final = "# Decoded from Base64+Zlib\n\n" + data
    return final