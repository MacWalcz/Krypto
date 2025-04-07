package org.krypto.logic;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileDao {

    public static List<byte[]> read(String fileName) {
        List<byte[]> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] buffer = new byte[8];

            while (( fis.read(buffer)) != -1) {
               // Skopiuj zawartość bufora do nowej tablicy
                blocks.add(buffer.clone());
            }
            return blocks;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    public static void write(List<byte[]> stream, String fileName) {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            for (int i = 0; i < stream.size(); i++) {
                byte[] block = stream.get(i);
                    fos.write(block);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
