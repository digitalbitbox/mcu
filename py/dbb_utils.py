#!/usr/bin/env python


import os
import sys
import json
import base64
import pyaes
import hid # hidapi (requires cython)
import hashlib
import struct
import hmac


# ----------------------------------------------------------------------------------
#

applen = 225280 # flash size minus bootloader length
chunksize = 8*512
usb_report_size = 64 # firmware > v2.0
report_buf_size = 4096 # firmware v2.0.0
boot_buf_size_send = 4098
boot_buf_size_reply = 256

sha256_byte_len = 32

# ----------------------------------------------------------------------------------
# Crypto
#

def aes_encrypt_with_iv(key, iv, data):
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Encrypter(aes_cbc)
    e = aes.feed(data) + aes.feed()  # empty aes.feed() appends pkcs padding
    return e


def aes_decrypt_with_iv(key, iv, data):
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Decrypter(aes_cbc)
    s = aes.feed(data) + aes.feed()  # empty aes.feed() strips pkcs padding
    return s


def encrypt_aes(key, s):
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(key, iv, s)
    e = iv + ct
    return e


def decrypt_aes(key, e):
    iv, e = e[:16], e[16:]
    s = aes_decrypt_with_iv(key, iv, e)
    return s


def sha256(x):
    return hashlib.sha256(x).digest()

def sha512(x):
    return hashlib.sha512(x).digest()

def double_hash(x):
    if type(x) is not bytearray: x=x.encode('utf-8')
    return sha256(sha256(x))

def derive_keys(x):
    h = double_hash(x)
    h = sha512(h)
    return (h[:int(len(h)/2)],h[int(len(h)/2):])

# ----------------------------------------------------------------------------------
# HID
#
def getHidPath():
    for d in hid.enumerate(0, 0):
        if d['vendor_id'] == 0x03eb and d['product_id'] == 0x2402:
            if d['interface_number'] == 0 or d['usage_page'] == 0xffff:
                # hidapi is not consistent across platforms
                # usage_page works on Windows/Mac; interface_number works on Linux
                return d['path']


dbb_hid = hid.device()
def openHid():
    print("\nOpening device")
    try:
        dbb_hid.open_path(getHidPath())
        print("\tManufacturer: %s" % dbb_hid.get_manufacturer_string())
        print("\tProduct: %s" % dbb_hid.get_product_string())
        print("\tSerial No: %s\n\n" % dbb_hid.get_serial_number_string())
    except:
        print("\nDevice not found\n")
        sys.exit()


# ----------------------------------------------------------------------------------
# Firmware io (keep consistent with the Electrum plugin)
#

HWW_CID = 0xFF000000
HWW_CMD = 0x80 + 0x40 + 0x01

def hid_send_frame(data):
    data = bytearray(data)
    data_len = len(data)
    seq = 0
    idx = 0
    write = []
    while idx < data_len:
        if idx == 0:
            # INIT frame
            write = data[idx : idx + min(data_len, usb_report_size - 7)]
            dbb_hid.write(b'\0' + struct.pack(">IBH",HWW_CID, HWW_CMD, data_len & 0xFFFF) + write + b'\xEE' * (usb_report_size - 7 - len(write)))
        else:
            # CONT frame
            write = data[idx : idx + min(data_len, usb_report_size - 5)]
            dbb_hid.write(b'\0' + struct.pack(">IB", HWW_CID, seq) + write + b'\xEE' * (usb_report_size - 5 - len(write)))
            seq += 1
        idx += len(write)


def hid_read_frame():
    # INIT response
    read = dbb_hid.read(usb_report_size)
    cid = ((read[0] * 256 + read[1]) * 256 + read[2]) * 256 + read[3]
    cmd = read[4]
    data_len = read[5] * 256 + read[6]
    data = read[7:]
    idx = len(read) - 7
    while idx < data_len:
        # CONT response
        read = dbb_hid.read(usb_report_size)
        data += read[5:]
        idx += len(read) - 5
    assert cid == HWW_CID, '- USB command ID mismatch'
    assert cmd == HWW_CMD, '- USB command frame mismatch'
    return data


def hid_send_plain(msg):
    print("Sending: {}".format(msg))
    if type(msg) == str:
        msg = msg.encode()
    reply = ""
    try:
        serial_number = dbb_hid.get_serial_number_string()
        if serial_number == "dbb.fw:v2.0.0" or serial_number == "dbb.fw:v1.3.2" or serial_number == "dbb.fw:v1.3.1":
            print('Please upgrade your firmware: digitalbitbox.com/firmware')
            sys.exit()
        hid_send_frame(msg)
        r = hid_read_frame()
        r = bytearray(r).rstrip(b' \t\r\n\0')
        r = ''.join(chr(e) for e in r)
        reply = json.loads(r)
        print("Reply:   {}".format(reply))
    except Exception as e:
        print('Exception caught ' + str(e))
    return reply

def hid_send_encrypt(msg, password):
    print("Sending: {}".format(msg))
    reply = ""
    try:
        encryption_key, authentication_key = derive_keys(password)
        msg = encrypt_aes(encryption_key, msg)
        hmac_digest = hmac.new(authentication_key, msg, digestmod=hashlib.sha256).digest()
        authenticated_msg = base64.b64encode(msg + hmac_digest)
        reply = hid_send_plain(authenticated_msg)
        if 'ciphertext' in reply:
            b64_unencoded = bytes(base64.b64decode(''.join(reply["ciphertext"])))
            reply_hmac = b64_unencoded[-sha256_byte_len:]
            hmac_calculated = hmac.new(authentication_key, b64_unencoded[:-sha256_byte_len], digestmod=hashlib.sha256).digest()
            if not hmac.compare_digest(reply_hmac, hmac_calculated):
                raise Exception("Failed to validate HMAC")
            reply = decrypt_aes(encryption_key, b64_unencoded[:-sha256_byte_len])
            print("Reply:   {}\n".format(reply))
            reply = json.loads(reply)
        if 'error' in reply:
            password = None
            print("\n\nReply:   {}\n\n".format(reply))
    except Exception as e:
        print('Exception caught ' + str(e))
    return reply


# ----------------------------------------------------------------------------------
# Bootloader io
#

def sendBoot(msg):
    msg = bytearray(msg) + b'\0' * (boot_buf_size_send - len(msg))
    serial_number = dbb_hid.get_serial_number_string()
    if 'v1.' in serial_number or 'v2.' in serial_number:
        dbb_hid.write(b'\0' + msg)
    else:
        # Split `msg` into 64-byte packets
        n = 0
        while n < len(msg):
            dbb_hid.write(b'\0' + msg[n : n + usb_report_size])
            n = n + usb_report_size


def sendPlainBoot(msg):
    print("\nSending: {}".format(msg))
    if type(msg) == str:
        msg = msg.encode()
    sendBoot(msg)
    reply = []
    while len(reply) < boot_buf_size_reply:
        reply = reply + dbb_hid.read(boot_buf_size_reply)

    reply = bytearray(reply).rstrip(b' \t\r\n\0')
    reply = ''.join(chr(e) for e in reply)
    print("Reply:   {} {}\n\n".format(reply[:2], reply[2:]))
    return reply


def sendChunk(chunknum, data):
    b = bytearray(b"\x77\x00")
    b[1] = chunknum % 0xFF
    b.extend(data)
    sendBoot(b)
    reply = []
    while len(reply) < boot_buf_size_reply:
        reply = reply + dbb_hid.read(boot_buf_size_reply)
    reply = bytearray(reply).rstrip(b' \t\r\n\0')
    reply = ''.join(chr(e) for e in reply)
    print("Loaded: {}  Code: {}".format(chunknum, reply))


def sendBin(filename):
    with open(filename, "rb") as f:
        cnt = 0
        while True:
            data = f.read(chunksize)
            if len(data) == 0:
                break
            sendChunk(cnt, data)
            cnt += 1
