#!/usr/bin/python3

""" pyvmx-cracker.py: Simple tool to crack VMX encryption passwords """

__author__ = 'axcheron'
__license__ = 'MIT License'
__version__ = '0.1'

from urllib.parse import unquote
from Crypto.Cipher import AES
from binascii import hexlify
import argparse
import hashlib
import random
import base64
import sys
import re

ks_re = '.+phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\)'

ks_struct = {
    'id': None,
    'password_hash': None,
    'password_cipher': None,
    'hash_round': None,
    'salt': None,
    'config_hash': None,
    'dict': None
}


def print_ksdata(keysafe):
    print("[*] KeySafe information...")
    print("\tID = %s" % keysafe['id'])
    print("\tHash = %s" % keysafe['password_hash'])
    print("\tAlgorithm = %s" % keysafe['password_cipher'])
    print("\tConfig Hash = %s" % keysafe['config_hash'])
    print("\tSalt = %s" % hexlify(keysafe['salt']).decode())


def crack_keysafe(keysafe, dict):
    wordlist = open(dict, 'r')
    count = 0

    print("\n[*] Starting bruteforce...")

    for line in wordlist.readlines():

        dict_key = hashlib.pbkdf2_hmac('sha1', line.rstrip().encode(), keysafe['salt'],
                                       keysafe['hash_round'], 32)

        dict_aes_iv = keysafe['dict'][:AES.block_size]
        cipher = AES.new(dict_key, AES.MODE_CBC, dict_aes_iv)
        dict_dec = cipher.decrypt(keysafe['dict'][AES.block_size:-20])

        if random.randint(1, 20) == 12:
            print("\t%d password tested..." % count)
        count += 1

        try:
            if 'type=key:cipher=AES-256:key=' in dict_dec.decode():
                print("\n[*] Password Found = %s" % line.rstrip())
                exit(0)
        except UnicodeDecodeError:
            pass

    print("\n[-] Password Not Found. You should try another dictionary.")


def parse_keysafe(file):
    try:
        with open(file, 'r') as data:
            lines = data.readlines()
    except (OSError, IOError):
        sys.exit('[-] Cannot read from file ' + data)

    for line in lines:
        if 'encryption.keySafe' in line:
            keysafe = line

    keysafe = unquote(keysafe)

    match = re.match(ks_re, keysafe)
    if not match:
        msg = 'Unsupported format of the encryption.keySafe line:\n' + keysafe
        raise ValueError(msg)

    vmx_ks = ks_struct

    vmx_ks['id'] = hexlify(base64.b64decode(match.group(1))).decode()
    vmx_ks['password_hash'] = match.group(2)
    vmx_ks['password_cipher'] = match.group(3)
    vmx_ks['hash_round'] = int(match.group(4))
    vmx_ks['salt'] = base64.b64decode(unquote(match.group(5)))
    vmx_ks['config_hash'] = match.group(6)
    vmx_ks['dict'] = base64.b64decode(match.group(7))

    return vmx_ks


def check_files(vmx, dict):
    try:
        with open(vmx, 'r') as data:
            lines = data.readlines()
    except (OSError, IOError):
        sys.exit('[-] Cannot read from file ' + vmx)

    if all('encryption.keySafe' not in line for line in lines):
        sys.exit('[-] Invalid VMX file or the VMX is not encrypted')

    try:
        passf = open(dict, 'rb')
    except IOError:
        print('[-] Cannot open wordlist (%s)' % dict)
        exit(1)


def pyvmx(vmx, dict):

    print("Starting pyvmx-cracker...\n")

    # Some validation...
    check_files(vmx, dict)
    # Map KeyStore to Dict
    parsed_ks = parse_keysafe(vmx)
    # Print info
    print_ksdata(parsed_ks)
    # Crack keysafe
    crack_keysafe(parsed_ks, dict)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Simple tool to crack VMware VMX encryption passwords")

    # Add arguments
    parser.add_argument("-v", "--vmx", dest="vmx", action="store",
                        help=".vmx file", type=str)

    parser.add_argument("-d", "--dict", dest="dict", action="store",
                        help="password list", type=str)

    args = parser.parse_args()

    if args.vmx and args.dict:
        pyvmx(args.vmx, args.dict)
    else:
        parser.print_help()
        exit(1)
