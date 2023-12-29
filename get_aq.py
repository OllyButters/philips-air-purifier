#!/usr/bin/env python3

import hashlib
import json
from Cryptodome.Cipher import AES
from coapthon import defines
from coapthon.client.helperclient import HelperClient
from pprint import pprint

def main():
    ####################
    SECRET_KEY = "JiangPan"   # I don't understand where this comes from, but it seems to be required. From decompiled app?
    #ip_address = "192.168.1.48"         # Bedroom
    ip_address = "192.168.1.65"         # Dining room
    port = 5683
    path = "/sys/dev/status"
    timeout = 60
    MAX_ATTEMPTS = 5
    debug = True

    ####################
    def _handle_AES(id):
        key_and_iv = hashlib.md5((SECRET_KEY + id).encode()).hexdigest().upper()
        half_keylen = len(key_and_iv) // 2
        secret_key = key_and_iv[0:half_keylen]
        iv = key_and_iv[half_keylen:]
        return AES.new(
            bytes(secret_key.encode("utf8")), AES.MODE_CBC, bytes(iv.encode("utf8"))
        )


    # Build request
    client = HelperClient(server=(ip_address, port))
    request = client.mk_request(defines.Codes.GET, path)

    # Send request, up to MAX_ATTEMPTS times
    request.observe = 0
    response = None
    attempts = 1
    while response is None and attempts <= MAX_ATTEMPTS:
        if debug:
            print("Connection attempt number: ", attempts, " of ", MAX_ATTEMPTS)
        response = client.send_request(request, None, timeout)
        if debug:
            print("Response: ")
            print(response)
        attempts += 1

    # Catch if we didn't get a response

    # This will give a hexadecimal response, which is the encrypted payload
    encrypted_payload = response.payload

    if debug:
        print("\nLength of encrypted payload: ")
        print(len(str(encrypted_payload)))

    # Now we need to decrypt the payload
    i = 1440
    offset = 8

    # There are 8 bytes of counter at the beginning of the payload, then by trail and error 1472 - 32 (1440)
    encoded_message = encrypted_payload[offset:offset+i]
    if debug:
        print("\nEncoded message: ")
        print(encoded_message)

    encoded_counter = encrypted_payload[0:8]
    aes = _handle_AES(encoded_counter)

    # This will be the decrypted payload, but still encoded, i.e. a byte string. 
    # There may be some padding at the end (\x02), which I rstrip here?
    decrypted_message = aes.decrypt(bytes.fromhex(encoded_message)).rstrip(b'\x01\x02')
    if debug:
        print("\nDecrypted message: ")
        print(decrypted_message)

    # Decode to utf8
    decoded_message = decrypted_message.decode('utf-8')
    if debug:
        print("\nDecoded message: ")
        print(decoded_message)       

    # I was using the unpad function from the padding module, but it seems to be unnecessary
    #unpaded_message = unpad(decrypted_message, 16, style="pkcs7")
    #unpaded_message = unpad(decoded_message, 16, style="pkcs7")
    #print(unpaded_message)

    # Now we have a JSON string, which we can parse
    if decoded_message is not None:
        #temp = json.loads(decoded_message[:-2])[
        json_message = json.loads(decoded_message)[
                "state"
            ]["reported"]
        if debug:
            print("\nJSON message: ")
            print(json_message)

        data = {}
        data['name'] = {'description': 'Name', 'value': json_message['name']}
        data['type'] = {'description': 'Type', 'value': json_message['type']}
        data['pm25'] = {'description': 'PM2.5', 'value': json_message['pm25']}
        data['iaql'] = {'description': 'Allergen index', 'value': json_message['iaql']}
        data['tvoc'] = {'description': 'Total volatile organic compounds', 'value': json_message['tvoc']}

        if debug:
            print("\nData: ")
        pprint(data)

        

if __name__ == "__main__":
    main()
