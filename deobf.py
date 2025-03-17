import base64
import zlib
import re
import sys

def decode_recursive(data, is_reversed):
    while True:
        match = re.search(r"b'([^']+)'", data) # extracting base64 encoded string between ('')
        if not match:
            print("No more base64 data found.")
            print("Final data:", data)
            break
        if is_reversed == 1:
            encoded_data = match.group(1)[::-1]
        else:
            encoded_data = match.group(1)
        try:
            decoded = base64.b64decode(encoded_data)
            #print("Decoded data:", decoded)
            try:
                decompressed = zlib.decompress(decoded)
                print("-" * 30)
                print("Decompressed data: \n", decompressed.decode())
                data = decompressed.decode()
            except zlib.error:
                print("No zlib compression detected.")
                break
        except Exception as e:
            print(f"Decoding failed: {e}")
            break

def args_handling():
    is_reversed = 0
    if len(sys.argv) == 1:
        return is_reversed
    if sys.argv[1] == "-h" or sys.argv[1] == "--help":
        print("Usage: python3 lam.py [OPTION]")
        print("Options:")
        print("  -r, --reverse  Reverse the base64 encoded string before decoding.")
        print("  -h, --help     Display this help message.")
        sys.exit(0)
    if sys.argv[1] == "-r" or sys.argv[1] == "--reverse":
        is_reversed = 1
    else:
        print("Invalid option. Use -h or --help for usage.")
        sys.exit(1)
    return is_reversed

if __name__ == "__main__":
    # usage: python3 deobf.py [OPTION]
    is_reversed = args_handling()
    #if is_reversed == 1:
        #print("reversing base64 string before decoding...")
    
    input_data = b"exec((_)(b'some_base64_encoded_data_here'))"
    decode_recursive(input_data.decode(), is_reversed)
