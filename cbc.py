# AES.CBC加密

# CBC加密需要key(密钥)iv(偏移量)
# 秘钥、明文、偏移量的数据类型均为bytes
# 秘钥必须为16字节或者16字节的倍数的字节型数据
# 明文必须为16字节的倍数的字节型数据，不够16字节需要进行补全。
# gbk编码：一个汉字两个字节
# utf-8：一个汉字三个字节
# 另外一种情况，密文是经过base64编码的(这种也是非常常见的，很多网站也是这样使用的)
# 有一些AES加密，所用的秘钥，或者IV向量是通过base64编码或者hexstr编码后的。针对这种，首先要进行的就是进行解码，都转换回bytes数据。

# 填充模式
# PKCS7Padding	当需要N个数据才能对齐时，填充字节型数据为N、并且填充N个


from base64 import b64encode,b64decode

from Crypto.Cipher import AES


class CBC:

    def __init__(self, key, iv, data=None, cipher=None):
        self.key = key.encode()
        self.iv = iv.encode()

        try:
            self.data = data.encode()
        except AttributeError:
            pass

        try:
            self.cipher = cipher.encode()
        except AttributeError:
            pass

        # 创建加密器
        self.aes = AES.new(key=self.key, IV=self.iv, mode=AES.MODE_CBC)

    # 加密补位
    def PKCS7Padding(self):
        pad = 16 - len(self.data) % 16
        self.data += (chr(pad).encode()) * pad
        return self.data

    @staticmethod
    # 解密去尾
    def cut_tail(over_data):
        data = over_data[:-ord(over_data[-1])]
        return data

    def Encryption(self):
        padded_data = CBC.PKCS7Padding(self)
        encryped_data = self.aes.encrypt(padded_data)
        # 至此，cbc加密已经完成，返回bytes
        # b'\x90\xa6[\x08\x96*?\x9c\xd1\xaf{\xc6\xd6\x96FP'

        cipher = b64encode(encryped_data)
        # 至此,base64编码完成
        # b'kKZbCJYqP5zRr3vG1pZGUA=='

        # 对字节进行解码，成为人类看得懂的字符串
        return cipher.decode()

    def Decryption(self):
        cipher = b64decode(self.cipher)
        # 先用base64让之现形
        # b'\x90\xa6[\x08\x96*?\x9c\xd1\xaf{\xc6\xd6\x96FP'

        padded_data = self.aes.decrypt(cipher).decode()

        data = CBC.cut_tail(padded_data)

        return data