package org.krypto.logic;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileDao {

    public static List<byte[]> read(String fileName) {
        List<byte[]> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] buffer = new byte[8];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                if (bytesRead < 8) {
                    // Uzupełnij brakujące bajty zerami
                    for (int i = bytesRead; i < 8; i++) {
                        buffer[i] = 0;
                    }
                }
                // Skopiuj zawartość bufora do nowej tablicy
                blocks.add(buffer.clone());
            }
            return blocks;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    public static void write(List<byte[]> stream, String fileName)  {
        try (FileOutputStream fis = new FileOutputStream(fileName)){
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fis);
            objectOutputStream.writeObject(stream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
