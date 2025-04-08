package org.krypto.logic;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Converter {
    public static String fromByteToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    public static byte[] fromBase64ToByte(String base64){
        return Base64.getDecoder().decode(base64);
    }

    public static String fromListBytesToBase64(List<byte[]> data) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] block : data) {
            baos.write(block, 0, block.length);

        }

        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    public static List<byte[]> fromBase64ToList(String base64, int blockSize) {
        byte[] allBytes = Base64.getDecoder().decode(base64);

        List<byte[]> list = new ArrayList<>();

        for (int i = 0; i < allBytes.length; i += blockSize) {
            int len = Math.min(blockSize, allBytes.length - i); // jeśli nie dzieli sie przez 8 bajtów to zostawia nie pełne
            byte[] block = new byte[len];
            System.arraycopy(allBytes, i, block, 0, len);

            list.add(block);
        }
        return list;
    }

    public static List<byte[]> fromUTF8ToList(String utf,int blockSize) {
        byte[] byteArray = utf.getBytes();

        List<byte[]> byteList = new ArrayList<>();


        for (int i = 0; i < byteArray.length; i += blockSize) {
            int len = Math.min(blockSize, byteArray.length - i);
            byte[] block = new byte[len];  // tu też moze być blok mniejszy niż 8
            System.arraycopy(byteArray, i, block, 0, len);
            byteList.add(block);
        }

        return byteList;
    }

    public static String fromListToUTF8(List<byte[]> data) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] block : data) {
            try {
                baos.write(block);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return baos.toString(StandardCharsets.UTF_8);
    }

    }


