import base64
import binascii
from io import BytesIO

import PIL
import numpy as np
from PIL import Image
from imageio import imread
from matplotlib.pyplot import imshow

from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
# 读取图片的像素值构成bytes
im = np.array(Image.open("..\\logo.png"))
value=bytes(im)

key = b'3l5butlj26hvv313'
#value = b'111'
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
crypt_sm4 = CryptSM4()

crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_ecb(value)
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)
assert value == decrypt_value
image1=Image.frombytes(mode="RGBA",size=(260,220),data=encrypt_value,decoder_name="raw")
image1.save("..\\logo_ECB_En.png")

image2=Image.frombytes(mode="RGBA",size=(260,220),data=decrypt_value,decoder_name="raw")
image2.save("..\\logo_ECB_De.png")

crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_cbc(iv , value)
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_cbc(iv , encrypt_value)
assert value == decrypt_value
image1=Image.frombytes(mode="RGBA",size=(260,220),data=encrypt_value,decoder_name="raw")
image1.save("..\\logo_CBC_En.png")
image2=Image.frombytes(mode="RGBA",size=(260,220),data=decrypt_value,decoder_name="raw")
image2.save("..\\logo_CBC_De.png")