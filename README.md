# security
AES encrypt with ECB model and base64 encode


#//encrypt:
#//*********先判断用AES-128 AES-192 AES-256哪种块大小，用pcks7方式填充。
#//*********填充后，AES加密
#//*********base64编码

#//decrypt:
#//*********base64解码
#//*********先判断用AES-128 AES-192 AES-256哪种块大小，AES解密
#//*********去掉填充

# GetKey(encryptKeyType int)
# 根据encryptKeyType判断密钥为何种密钥，并返回密钥

# AesEncryptNonBase64(data []byte, key string)
# 根据data和密钥进行填充及AES加密，ECB模式

# AesEncrypt(data []byte, key string)
# 将AesEncryptNonBase64(data []byte, key string)所得结果进行base64编码

# AesDecrypt(data string, key string)
# base64解码并解码、去掉填充