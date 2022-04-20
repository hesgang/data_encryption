#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time : 2022/4/20 14:45 
# @Author : hesgang
# @File : conf.py 

import os
import time
from datetime import datetime
import shutil
import rsa
import base64


class DataEncrypt(object):
    def __init__(self):
        # U盘的盘符
        self.usb_path = 'H:/'
        self.pri_file = r"H:\hsg"

    def __get_pri(self):
        """
        获取私钥信息
        return: pri key
        """
        if os.path.exists(self.usb_path) and os.path.exists(self.pri_file):
            with open(self.pri_file, 'rb') as f:
                dd = f.read()
                decode_str = base64.decodebytes(dd)
                return decode_str
        else:
            return None

    def text_encrypt(self, msg: str):
        """数据加密"""
        msg = msg.encode('utf-8')
        length = len(msg)
        default_length = 245
        # 长度不用分段
        if length < default_length:
            return base64.b64encode(self._encrypt(msg))
        # 需要分段
        offset = 0
        res = []
        while length - offset > 0:
            if length - offset > default_length:
                res.append(self._encrypt(msg[offset:offset + default_length]))
            else:
                res.append(self._encrypt(msg[offset:]))
            offset += default_length
        byte_data = b''.join(res)
        return base64.b64encode(byte_data)

    def text_decrypt(self, msg: bytes):
        """数据解密"""
        msg = base64.b64decode(msg)
        length = len(msg)
        default_length = 256
        # 长度不用分段
        if length < default_length:
            return b''.join(self._decrypt(msg))
        # 需要分段
        offset = 0
        res = []
        while length - offset > 0:
            if length - offset > default_length:
                res.append(self._decrypt(msg[offset:offset + default_length]))
            else:
                res.append(self._decrypt(msg[offset:]))
            offset += default_length

        return b''.join(res).decode('utf8')

    def _decrypt(self, crypt_text: bytes):  # 用私钥解密
        p = self.__get_pri()
        private_key = rsa.PrivateKey.load_pkcs1(p)
        lase_text = rsa.decrypt(crypt_text, private_key)
        return lase_text  # 解密后的明文

    @staticmethod
    def _encrypt(text: bytes):  # 用公钥加密
        with open('public.pem', 'rb') as publickfile:
            p = publickfile.read()
        pubkey = rsa.PublicKey.load_pkcs1(p)
        crypt_text = rsa.encrypt(text, pubkey)
        return crypt_text  # 加密后的密文


if __name__ == '__main__':
    te = Data()
    enc = te.text_encrypt('hello')
    print(enc)
    print(te.text_decrypt(enc))
