package com.github.deansquirrel.tools.secret;

import java.util.Arrays;
import java.util.Base64;

class SecretCommon {

    public static final Base64.Encoder encoder = Base64.getEncoder();
    public static final Base64.Decoder decoder = Base64.getDecoder();

    /**
     * 字节求异或
     * @param a 参数a
     * @param b 参数b
     * @return 结果
     */
    public static byte getXor(byte a, byte b) {
        return (byte)((int) a ^ (int) b);
    }

    /**
     * 16进制字符串转字节数组
     * @param s 参数
     * @return 数组
     */
    public static byte[] hexStr2Bytes(String s) {
        int l = s.length() / 2;
        byte[] ret = new byte[l];
        for (int i = 0; i < l; i++) {
            ret[i] = (byte)Integer.parseInt(s.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
    }

    /**
     * 字节数组合并
     * @param arg 字节数组
     * @return 结果
     */
    public static byte[] byteMerger(byte[] ...arg) {
        if(arg.length < 1) {
            return new byte[0];
        }
        int len = 0;
        for(byte[] d : arg) {
            len = len + d.length;
        }
        byte[] result = new byte[len];
        int currLen = 0;
        for (byte[] d : arg) {
            System.arraycopy(d, 0, result, currLen, d.length);
            currLen = currLen + d.length;
        }
        return result;
    }

    /**
     * 字符串解密
     * @param cipherText 密文
     * @param key 密钥
     * @return 解密后的字节数组
     * @throws Exception 异常信息
     */
    public static byte[] getDecryptByteFromBase64Format(String cipherText, String key) throws Exception {
        byte[] checkKeyByte, keyByte, resultByte;
        try{
            byte[] byteCipherText = SecretCommon.decoder.decode(cipherText);

            resultByte = new byte[byteCipherText.length - 4];
            System.arraycopy(byteCipherText, 4, resultByte, 0, resultByte.length);

            byte[] rndKey = new byte[4];
            System.arraycopy(byteCipherText, 0, rndKey, 0, 4);

            for (int i = 0; i < resultByte.length; i++) {
                resultByte[i] = SecretCommon.getXor(resultByte[i], rndKey[i % rndKey.length]);
            }

            keyByte = key.getBytes("GBK");
            for (int i = 0; i < resultByte.length; i++) {
                resultByte[i] = SecretCommon.getXor(resultByte[i], keyByte[i % keyByte.length]);
            }

            checkKeyByte = new byte[keyByte.length];
            System.arraycopy(resultByte, 16, checkKeyByte, 0, checkKeyByte.length);
        } catch (Exception e) {
            throw new Exception("解密失败。（非法文本）");
        }

        if(!Arrays.equals(checkKeyByte, keyByte)) {
            throw new Exception("解密失败。（密码非法）");
        }
        return resultByte;
    }

}
