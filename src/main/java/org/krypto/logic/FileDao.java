package org.krypto.logic;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileDao {
    //czyta z pliku dzieli na bloki nie robi paddingu
    public static List<byte[]> read(String fileName, int blockSize) {
        List<byte[]> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] buffer = new byte[8192]; // większy bufor (np. 8KB)
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                int start = 0;

                while (bytesRead - start >= blockSize) {
                    byte[] block = new byte[blockSize];
                    System.arraycopy(buffer, start, block, 0, blockSize);
                    blocks.add(block);
                    start += blockSize;
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
