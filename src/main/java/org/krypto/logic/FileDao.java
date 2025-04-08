package org.krypto.logic;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileDao {
    //czyta z pliku dzieli na bloki nie robi paddingu
    public static List<byte[]> read(String fileName) {
        List<byte[]> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] buffer = new byte[8192]; // większy bufor (np. 8KB)
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                int start = 0;

                while (bytesRead - start >= 8) {
                    byte[] block = new byte[8];
                    System.arraycopy(buffer, start, block, 0, 8);
                    blocks.add(block);
                    start += 8;
                }

                if (bytesRead - start > 0) {
                    byte[] lastBlock = new byte[bytesRead - start];
                    System.arraycopy(buffer, start, lastBlock, 0, bytesRead - start);
                    blocks.add(lastBlock);
                }
            }
            return blocks;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    public static void write(List<byte[]> stream, String fileName) {
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(fileName))) {
            for (byte[] block : stream) {
                bos.write(block);  // Zapisuje blok do bufora
            }
            bos.flush();  // Upewniamy się, że wszystkie dane zostały zapisane na dysk
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
