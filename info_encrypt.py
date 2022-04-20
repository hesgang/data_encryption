#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import rsa
import base64


def text_encrypt(msg):
    """数据加密"""
    msg = msg.encode('utf-8')
    length = len(msg)
    default_length = 245
    # 长度不用分段
    if length < default_length:
        return base64.b64encode(encrypt(msg))
    # 需要分段
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(encrypt(msg[offset:offset + default_length]))
        else:
            res.append(encrypt(msg[offset:]))
        offset += default_length
    byte_data = b''.join(res)
    return base64.b64encode(byte_data)


def text_decrypt(msg):
    """数据解密"""
    msg = base64.b64decode(msg)
    length = len(msg)
    default_length = 256
    # 长度不用分段
    if length < default_length:
        return b''.join(decrypt(msg))
    # 需要分段
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(decrypt(msg[offset:offset + default_length]))
        else:
            res.append(decrypt(msg[offset:]))
        offset += default_length

    return b''.join(res).decode('utf8')


def decrypt(crypt_text):  # 用私钥解密
    with open('private.pem', 'rb') as privatefile:
        p = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(p)
    lase_text = rsa.decrypt(crypt_text, privkey)

    return lase_text


def encrypt(text):  # 用公钥加密
    with open('public.pem', 'rb') as publickfile:
        p = publickfile.read()
    # print(p)
    pubkey = rsa.PublicKey.load_pkcs1(p)
    crypt_text = rsa.encrypt(text, pubkey)
    # print(type(crypt_text))
    return crypt_text  # 加密后的密文


def create_keys():  # 生成公钥和私钥
    (pubkey, privkey) = rsa.newkeys(2048)
    pub = pubkey.save_pkcs1()
    print(pub)
    with open('public.pem', 'wb+') as f:
        f.write(pub)

    pri = privkey.save_pkcs1()
    print(pri)
    with open('private.pem', 'wb+') as f:
        f.write(pri)


