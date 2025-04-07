package org.krypto.logic;

import java.util.Base64;

public class Converter {
    public static String fromByteToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    public static byte[] fromBase64ToByte(String base64){
        return Base64.getDecoder().decode(base64);
    }
}
