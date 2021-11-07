package com.github.deansquirrel.tools.secret;

import com.github.deansquirrel.tools.common.CommonTool;
import com.github.deansquirrel.tools.common.MathTool;

import java.util.Arrays;
import java.util.Base64;

/***
 * 加密工具类1
 * @author yuansong6@163.com
 */

public class SimpleOne {

    private SimpleOne(){}

    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();

    /***
     * 将明文加密为Base64格式的密文
     * @param plainText 原文
     * @param key 密码
     * @return 密文
     */
    public static String EncryptToBase64Format(String plainText, String key) throws Exception{

        if(plainText == null || key == null) {
            throw new Exception("原文或密码不可为空");
        }
        if(plainText.length() < 1 || key.length() < 1) {
            throw new Exception("原文或密码不可为空");
        }

        byte[] sPlain =(key + plainText).getBytes("GBK");

        String sMd5 = CommonTool.Md5Encode(sPlain);

        byte[] hexMd5 = hexStr2Bytes(sMd5) ;

        byte[] resultByte = byteMerger(hexMd5,sPlain);
        byte[] keyByte = key.getBytes("GBK");

        for(int i=0;i<resultByte.length;i++) {
            resultByte[i] = getXor(resultByte[i], keyByte[i % keyByte.length]);
        }

        byte[] rndKey = new byte[4];
        for(int i = 0; i < rndKey.length; i++) {
            rndKey[i] = (byte)(MathTool.RandInt(0, 64) & 0xFF);
        }

        for(int i = 0; i < resultByte.length; i++) {
            resultByte[i] = (byte) (resultByte[i] ^ (rndKey[i%rndKey.length]));
        }

        resultByte = byteMerger(rndKey, resultByte);

        return encoder.encodeToString(resultByte);
    }

    /***
     * 将Base64格式的密文解密
     * @param cipherText 密文
     * @param key 密码
     * @return 解密后的原文
     */
    public static String DecryptFromBase64Format(String cipherText, String key) throws Exception {
        byte[] checkKeyByte, keyByte, resultByte, sMd5Check, sMd5, plainByte;
        try {
            byte[] byteCipherText = decoder.decode(cipherText);

            resultByte = new byte[byteCipherText.length - 4];
            System.arraycopy(byteCipherText, 4, resultByte, 0, resultByte.length);
            byte[] rndKey = new byte[4];
            System.arraycopy(byteCipherText, 0, rndKey, 0, 4);

            for(int i = 0; i < resultByte.length; i++) {
                resultByte[i] = getXor(resultByte[i], rndKey[i % rndKey.length]);
            }

            keyByte = key.getBytes("GBK");
            for(int i = 0; i < resultByte.length; i++) {
                resultByte[i] = getXor(resultByte[i], keyByte[i % keyByte.length]);
            }

            checkKeyByte = new byte[keyByte.length];
            System.arraycopy(resultByte, 16, checkKeyByte, 0, checkKeyByte.length);

        } catch(Exception e) {
            throw new Exception("解密失败。（非法文本）");
        }

        if(!Arrays.equals(checkKeyByte, keyByte)) {
            throw new Exception("解密失败。（密码非法）");
        }

        try {
            sMd5Check = new byte[16];
            System.arraycopy(resultByte, 0, sMd5Check, 0, sMd5Check.length);
            plainByte = new byte[resultByte.length - (16 + keyByte.length)];
            System.arraycopy(resultByte, 16 + keyByte.length, plainByte, 0, plainByte.length);

            byte[] byteTemp = byteMerger(keyByte, plainByte);

            sMd5 = hexStr2Bytes(CommonTool.Md5Encode(byteTemp)) ;
        } catch(Exception e) {
            throw new Exception("解密失败。（非法文本）");
        }

        if(!Arrays.equals(sMd5Check, sMd5)) {
            throw new Exception("解密失败。（校验错误）");
        }

        return new String(plainByte, "GBK");
    }

    /**
     * 字节数组合并
     * @param bt1 参数1
     * @param bt2 参数2
     * @return 结果
     */
    private static byte[] byteMerger(byte[] bt1, byte[] bt2) {
        byte[] btResult = new byte[bt1.length + bt2.length];
        System.arraycopy(bt1, 0, btResult, 0, bt1.length);
        System.arraycopy(bt2, 0, btResult, bt1.length, bt2.length);
        return btResult;
    }

    /**
     * 16进制字符串转字节数组
     * @param s 参数
     * @return 数组
     */
    private static byte[] hexStr2Bytes(String s) {
        int l = s.length() / 2;
        byte[] ret = new byte[l];
        for (int i = 0; i < l; i++) {
            ret[i] = (byte)Integer.parseInt(s.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
    }

    /**
     * 字节求异或
     * @param a 参数a
     * @param b 参数b
     * @return 结果
     */
    private static byte getXor(byte a, byte b) {
        return (byte)((int) a ^ (int) b);
    }

}
