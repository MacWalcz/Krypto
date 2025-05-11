package org.krypto.logic;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Arrays;
import java.util.List;

public class FileDao {
    public static List<byte[]> read(String fileName, int blockSize) {
        List<byte[]> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] all = fis.readAllBytes();
            blocks = split(all, blockSize);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return blocks;
    }

    public static void write(List<byte[]> stream, String fileName) {
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(fileName))) {
            for (byte[] block : stream) bos.write(block);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void writeCipher(List<BigInteger[]> cipher, String fileName) {
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(fileName))) {
            dos.writeInt(cipher.size());
            for (BigInteger[] pair : cipher) {
                byte[] b1 = pair[0].toByteArray();
                byte[] b2 = pair[1].toByteArray();
                dos.writeInt(b1.length);
                dos.write(b1);
                dos.writeInt(b2.length);
                dos.write(b2);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static List<BigInteger[]> readCipher(String fileName) {
        List<BigInteger[]> list = new ArrayList<>();
        try (DataInputStream dis = new DataInputStream(new FileInputStream(fileName))) {
            int n = dis.readInt();
            for (int i = 0; i < n; i++) {
                byte[] b1 = new byte[dis.readInt()]; dis.readFully(b1);
                byte[] b2 = new byte[dis.readInt()]; dis.readFully(b2);
                list.add(new BigInteger[]{ new BigInteger(1, b1), new BigInteger(1, b2) });
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return list;
    }

    public static String cipherToString(List<BigInteger[]> cipher) {
        StringBuilder sb = new StringBuilder();
        for (BigInteger[] p : cipher) {
            sb.append(Base64.getEncoder().encodeToString(p[0].toByteArray()))
                    .append(":")
                    .append(Base64.getEncoder().encodeToString(p[1].toByteArray()))
                    .append("\n");
        }
        return sb.toString();
    }

    public static List<BigInteger[]> parseString(String text) {
        List<BigInteger[]> list = new ArrayList<>();
        String[] lines = text.split("\\r?\\n");
        for (String ln : lines) {
            ln = ln.trim();
            if (ln.isEmpty() || !ln.contains(":")) continue;
            String[] parts = ln.split("\\s*[:]\\s*");
            if (parts.length != 2) continue;
            try {
                byte[] b1 = Base64.getDecoder().decode(parts[0]);
                byte[] b2 = Base64.getDecoder().decode(parts[1]);
                list.add(new BigInteger[]{ new BigInteger(1, b1), new BigInteger(1, b2) });
            } catch (IllegalArgumentException e) {
                // pomijamy nieprawidłowe linie
            }
        }
        return list;
    }

    public static List<byte[]> split(byte[] data, int blockSize) {
        List<byte[]> blocks = new ArrayList<>();
        for (int i = 0; i < data.length; i += blockSize) {
            int len = Math.min(blockSize, data.length - i);
            blocks.add(Arrays.copyOfRange(data, i, i + len));
        }
        return blocks;
    }

    public static byte[] concat(List<byte[]> blocks) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] b : blocks) baos.writeBytes(b);
        return baos.toByteArray();
    }
}