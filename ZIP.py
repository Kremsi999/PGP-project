import base64
import pickle
import zlib


#zip funkcije ova za tuple ce mozda trebati pa je imamo
def zip_string(string):
    compressed_data = zlib.compress(bytes(string, 'utf-8'))
    return compressed_data.hex()


def unzip_string(zipped_string):
    compressed_data = bytes.fromhex(zipped_string)
    uncompressed_data = zlib.decompress(compressed_data)
    return uncompressed_data.decode('utf-8')


def zip_object(obj):
    serialized_obj = pickle.dumps(obj)
    compressed_data = zlib.compress(serialized_obj)
    return compressed_data.hex()


def unzip_object(zipped_obj):
    compressed_data = bytes.fromhex(zipped_obj)
    uncompressed_data = zlib.decompress(compressed_data)
    obj = pickle.loads(uncompressed_data)
    return obj


def convert_to_64(zipped_string):
    compressed = bytes.fromhex(zipped_string)
    string64 = base64.b64encode(compressed)
    return string64.decode()


def convert_to_zip(radix64):
    compressed = base64.b64decode(radix64)
    zipped_string = compressed.hex()
    return zipped_string


def string_to_radix64(input_string):
    encoded_bytes = base64.b64encode(input_string.encode())
    encoded_string = encoded_bytes.decode()
    return encoded_string


def radix64_to_string(encoded_string):
    decoded_bytes = base64.b64decode(encoded_string)
    decoded_string = decoded_bytes.decode()
    return decoded_string


def tuple_to_radix64(tuple_value):
    bytes_value = b''.join(tuple_value)
    radix64_str = base64.b64encode(bytes_value).decode()
    return radix64_str


def radix64_to_tuple(radix64_str, bytes2, bytes1):
    decoded_bytes = base64.b64decode(radix64_str.encode())
    tupleValue2 = bytes(decoded_bytes[0:bytes2])
    tupleValue1 = bytes(decoded_bytes[-bytes1:])
    return (tupleValue2, tupleValue1)


def string_to_hex(string_value):
    hex_bytes = string_value.encode().hex()
    return hex_bytes


def hex_to_string(hex_value):
    string_value = bytes.fromhex(hex_value).decode()
    return string_value
