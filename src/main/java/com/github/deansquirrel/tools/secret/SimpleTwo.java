package com.github.deansquirrel.tools.secret;

import com.github.deansquirrel.tools.common.CommonTool;
import com.github.deansquirrel.tools.common.MathTool;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SimpleTwo {

    private SimpleTwo(){}

    /***
     * 将明文加密为Base64格式的密文
     * @param plainText 原文
     * @param key 密码
     * @return 密文
     */
    public static String EncryptToBase64Format(String plainText, String key) throws Exception{
        String plainTextR = plainText == null ? "" : plainText;
        String keyR = key == null ? "" : key;

        byte[] sPlain = (keyR + plainTextR).getBytes("GBK");
        byte[] hexSMd5 = SecretCommon.hexStr2Bytes(CommonTool.Md5Encode(sPlain)) ;
        byte[] tCurr = String.valueOf(System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8);
        byte[] hexTMd5 = SecretCommon.hexStr2Bytes(CommonTool.Md5Encode(tCurr)) ;

        byte[] resultByte = SecretCommon.byteMerger(hexSMd5, sPlain, hexTMd5, tCurr);

        byte[] keyByte = keyR.getBytes("GBK");
        for(int i = 0; i < resultByte.length; i++){
            resultByte[i] = SecretCommon.getXor(resultByte[i], keyByte[i % keyByte.length]);
        }

        byte[] rndKey = new byte[4];
        for(int i = 0; i < rndKey.length; i++) {
            rndKey[i] = (byte)(MathTool.RandInt(0, 64) & 0xFF);
        }

        for(int i = 0; i < resultByte.length; i++) {
            resultByte[i] = SecretCommon.getXor(resultByte[i] , rndKey[i % rndKey.length]);
        }

        return SecretCommon.encoder.encodeToString(SecretCommon.byteMerger(rndKey, resultByte));
    }

    /***
     * 将Base64格式的密文解密
     * @param cipherText 密文
     * @param key 密码
     * @return 解密后的原文
     */
    public static String DecryptFromBase64Format(String cipherText, String key) throws Exception {
        return DecryptFromBase64Format(cipherText, key, -1L);
    }

    /**
     * 将Base64格式的密文解密
     * @param cipherText 密文
     * @param key 密码
     * @param timeout 密文有效时长
     * @return 解密后的原文
     * @throws Exception 异常
     */
    public static String DecryptFromBase64Format(String cipherText, String key, long timeout) throws Exception {
        byte[] keyByte, resultByte, plainByte, sMd5Check, tCheck, tMd5Check, hexSMd5, hexTMd5;
        long timestamp;
        resultByte = SecretCommon.getDecryptByteFromBase64Format(cipherText, key);
        try {
            keyByte = key.getBytes("GBK");

            tCheck = new byte[13];
            System.arraycopy(resultByte, resultByte.length - tCheck.length, tCheck, 0, tCheck.length);

            tMd5Check = new byte[16];
            System.arraycopy(resultByte, resultByte.length - (tMd5Check.length + tCheck.length) ,
                    tMd5Check, 0, tMd5Check.length);

            plainByte = new byte[resultByte.length - (16 + 16 + 13 + keyByte.length)];
            System.arraycopy(resultByte, 16 + keyByte.length, plainByte, 0, plainByte.length);

            sMd5Check = new byte[16];
            System.arraycopy(resultByte, 0, sMd5Check, 0, sMd5Check.length);

            hexSMd5 = SecretCommon.hexStr2Bytes(CommonTool.Md5Encode(SecretCommon.byteMerger(keyByte, plainByte)));
            hexTMd5 = SecretCommon.hexStr2Bytes(CommonTool.Md5Encode(tCheck));
            timestamp = Long.parseLong(new String(tCheck, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new Exception("解密失败。（非法文本）");
        }

        if(!Arrays.equals(sMd5Check, hexSMd5)
                || !Arrays.equals(tMd5Check, hexTMd5)) {
            throw new Exception("解密失败。（校验错误）");
        }

        if((timeout > 0 && Math.abs(System.currentTimeMillis() - timestamp) > timeout)) {
            throw new Exception("解密失败。（时间戳异常）");
        }

        return new String(plainByte, "GBK");
    }

    /***
     * 将Base64格式的密文解密
     * @param cipherText 密文
     * @param key 密码
     * @return 解密后的原文
     */
    public static long getDecryptTimestampFromBase64Format(String cipherText, String key) throws Exception {
        byte[] resultByte, tCheck;
        long timestamp;
        try {
            resultByte = SecretCommon.getDecryptByteFromBase64Format(cipherText, key);
            tCheck = new byte[13];
            System.arraycopy(resultByte, resultByte.length - tCheck.length, tCheck, 0, tCheck.length);
            timestamp = Long.parseLong(new String(tCheck, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new Exception("解密失败。（非法文本）");
        }
        return timestamp;
    }

}
