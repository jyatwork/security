# security
AES encrypt with ECB model and base64 encode


#//encrypt:
#//*********���ж���AES-128 AES-192 AES-256���ֿ��С����pcks7��ʽ��䡣
#//*********����AES����
#//*********base64����

#//decrypt:
#//*********base64����
#//*********���ж���AES-128 AES-192 AES-256���ֿ��С��AES����
#//*********ȥ�����

# GetKey(encryptKeyType int)
# ����encryptKeyType�ж���ԿΪ������Կ����������Կ

# AesEncryptNonBase64(data []byte, key string)
# ����data����Կ������估AES���ܣ�ECBģʽ

# AesEncrypt(data []byte, key string)
# ��AesEncryptNonBase64(data []byte, key string)���ý������base64����

# AesDecrypt(data string, key string)
# base64���벢���롢ȥ�����