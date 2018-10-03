# pyvmx-cracker

Based on the [VMwareVMX](https://github.com/RF3/VMwareVMX) module, this tool aims to crack VMX encryption passwords. This tool crack the password by successfully decrypting the *dict* structure. If you want to fully decrypt the VMX structure, check the [VMwareVMX](https://github.com/RF3/VMwareVMX) module.

## Description

The VMX files (.vmx) contains the virtual machine informations, VMware VMX configuration files are encrypted when the virtual machine is
encrypted. Here is a sample from an encrypted VMX file :

```bash
.encoding = "UTF-8"
displayName = "Encrypted"
encryption.keySafe = "vmware:key/list/(pair/(phrase/MA3fCocdhNc%3d/pass2key%3dPBKDF2%2dHMAC%2dSHA%2d1%3a
cipher%3dAES%2d256%3arounds%3d1000%3asalt%3d9kxr%2bxeqo4xPz9ttPZUVFA%253d%253d,
HMAC%2dSHA%2d1,X4sG4nJc0yeWAaSkBllAPI4nCrbO2RUE8dXHa82I4KmfNO7JjruuCrWgRRT6EUQHGQP%2bTDjPFSLHZ
s%2bwRpFZXpjyWvJkzwFhx7UJGQriz3SCXWlwrz1zNPYAmqSXiusyFiY4js0CdabNfdFQKtLy79jDuP0%3d))"
encryption.data = "..."
```

The KeyStore is a simple structure, and it contains the information needed by the machine to verify the password each time the user wants to start a machine or change its password. Here are some information about the *KeySafe* structure :

| Name | Description |
| ---- | ----------- | 
| id | Identifier must be 8 bytes long and is just a random number | 
| password_hash | Only PBKDF2-HMAC-SHA-1 algorithm for the password is supported | 
| password_cipher | Only AES-256 encryption algorithm for the dictionary is supported | 
| hash_round | Hash rounds | 
| salt | The salt parameter is used with the password for the PBKDF2-HMAC-SHA-1 | 
| config_hash | Only HMAC-SHA-1 hash algorithm for the configuration is supported | 
| dict | Dictionary (starts with 'type=key:cipher=AES-256:key=' when successfully decrypted) | 


## Requirements

This tool requires the [pyCrypto](https://www.dlitz.net/software/pycrypto/) module. You can install it from the requirements file :

```bash
$ pip3 install -r requirements.txt
```

You also can install it directly :

```bash
$ pip3 pip install pyCrypto
```

## Install

Checkout the source: `git clone https://github.com/axcheron/pyvmx-cracker.git`

## Getting Started

```bash
$ python3 pyvmx-cracker.py
usage: pyvmx-cracker.py [-h] [-v VMX] [-d DICT]

Simple tool to crack VMware VMX encryption passwords

optional arguments:
  -h, --help            show this help message and exit
  -v VMX, --vmx VMX     .vmx file
  -d DICT, --dict DICT  password list

$ python3 pyvmx-cracker.py -v sample.vmx -d wordlist.txt
Starting pyvmx-cracker...

[*] KeySafe information...
        ID = 300ddf0a871d84d7
        Hash = PBKDF2-HMAC-SHA-1
        Algorithm = AES-256
        Config Hash = HMAC-SHA-1
        Salt = f64c6bfb17aaa38c4fcfdb6d3d951514

[*] Starting bruteforce...
        9 password tested...
        20 password tested...
        40 password tested...
        111 password tested...
        128 password tested...
        136 password tested...
        140 password tested...
        154 password tested...
        180 password tested...
        209 password tested...

[*] Password Found = Password123
```

## Resources

Here are some interesting resources about this project :

- https://github.com/RF3/VMwareVMX

## License

This project is released under the MIT License. See LICENCE file.