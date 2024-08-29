package com.github.deansquirrel.tools.secret;

import com.github.deansquirrel.tools.common.CommonTool;
import com.github.deansquirrel.tools.common.MathTool;

import java.util.Arrays;

public class SimpleOne {

    private SimpleOne(){}

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
        if(plainText.isEmpty() || key.isEmpty()) {
            throw new Exception("原文或密码不可为空");
        }

        byte[] sPlain =(key + plainText).getBytes("GBK");

        String sMd5 = CommonTool.Md5Encode(sPlain);

        byte[] hexMd5 = SecretCommon.hexStr2Bytes(sMd5) ;

        byte[] resultByte = SecretCommon.byteMerger(hexMd5,sPlain);
        byte[] keyByte = key.getBytes("GBK");

        for(int i=0;i<resultByte.length;i++) {
            resultByte[i] = SecretCommon.getXor(resultByte[i], keyByte[i % keyByte.length]);
        }

        byte[] rndKey = new byte[4];
        for(int i = 0; i < rndKey.length; i++) {
            rndKey[i] = (byte)(MathTool.RandInt(0, 64) & 0xFF);
        }

        for(int i = 0; i < resultByte.length; i++) {
            resultByte[i] = (byte) (resultByte[i] ^ (rndKey[i%rndKey.length]));
        }

        resultByte = SecretCommon.byteMerger(rndKey, resultByte);

        return SecretCommon.encoder.encodeToString(resultByte);
    }

    /***
     * 将Base64格式的密文解密
     * @param cipherText 密文
     * @param key 密码
     * @return 解密后的原文
     */
    public static String DecryptFromBase64Format(String cipherText, String key) throws Exception {
        byte[] keyByte, resultByte, sMd5Check, sMd5, plainByte;
        resultByte = SecretCommon.getDecryptByteFromBase64Format(cipherText, key);

        try {
            keyByte = key.getBytes("GBK");
            sMd5Check = new byte[16];
            System.arraycopy(resultByte, 0, sMd5Check, 0, sMd5Check.length);
            plainByte = new byte[resultByte.length - (16 + keyByte.length)];
            System.arraycopy(resultByte, 16 + keyByte.length, plainByte, 0, plainByte.length);

            byte[] byteTemp = SecretCommon.byteMerger(keyByte, plainByte);

            sMd5 = SecretCommon.hexStr2Bytes(CommonTool.Md5Encode(byteTemp)) ;
        } catch(Exception e) {
            throw new Exception("解密失败。（非法文本）");
        }

        if(!Arrays.equals(sMd5Check, sMd5)) {
            throw new Exception("解密失败。（校验错误）");
        }

        return new String(plainByte, "GBK");
    }


}
