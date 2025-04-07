package org.krypto.logic;


import java.util.Arrays;
import java.util.List;

public class Padding {

    // Przykład PKCS7: jeżeli ostatni blok ma n bajtów, to do 8 bajtów
    // dopełniamy (8 - n) bajtami, z których każdy ma wartość (8 - n).
    public static void padMessage(List<byte[]> blocks) {
        // Jeżeli brak bloków -> nic nie robimy
        if (blocks == null || blocks.isEmpty()) {
            return;
        }

        // Można też wyeliminować puste bloki, jeśli takie wystąpiły
        // (opcjonalnie):
        blocks.removeIf(b -> b == null || b.length == 0);

        // Ponownie sprawdzamy, czy nie zrobiło się pusto
        if (blocks.isEmpty()) {
            // W razie potrzeby można dodać tutaj
            // 1 blok wypełniony 0x08 itp.
            return;
        }

        // Bierzemy ostatni blok
        byte[] lastBlock = blocks.get(blocks.size() - 1);
        int lastBlockLen = lastBlock.length;

        if (lastBlockLen < 8) {
            // Ile bajtów trzeba dopakować
            int padCount = 8 - lastBlockLen;
            byte[] newBlock = Arrays.copyOf(lastBlock, 8);
            // Wstawiamy bajty o wartości padCount
            for (int i = lastBlockLen; i < 8; i++) {
                newBlock[i] = (byte) padCount;
            }
            blocks.set(blocks.size() - 1, newBlock);
        } else if (lastBlockLen == 8) {
            // Dodatkowy blok z samymi bajtami = 08
            // w PKCS7, aby dać znać o pełnym bloku
            byte[] extra = new byte[8];
            Arrays.fill(extra, (byte) 8);
            blocks.add(extra);
        } else {
            // Jeżeli ktoś dał blok > 8, można np. dzielić na 8-bajtowe segmenty
            // lub zgłosić błąd.
            throw new IllegalArgumentException("Block has length > 8. Possibly already chunked incorrectly?");
        }
    }

    // Przykładowy unpad (PKCS7)
    public static void unpadMessage(List<byte[]> blocks) {
        if (blocks == null || blocks.isEmpty()) {
            return;
        }
        // Bierzemy ostatni blok
        byte[] lastBlock = blocks.get(blocks.size() - 1);
        if (lastBlock.length != 8) {
            // coś nie tak...
            return;
        }
        // Liczba bajtów do usunięcia
        int padVal = lastBlock[7] & 0xFF;
        if (padVal < 1 || padVal > 8) {
            // no to nie wygląda jak PKCS7
            return;
        }
        // sprawdzamy, czy faktycznie tyle bajtów wypełnienia jest
        for (int i = 8 - padVal; i < 8; i++) {
            if ((lastBlock[i] & 0xFF) != padVal) {
                // Nie pasuje do PKCS7
                return;
            }
        }
        // kopiujemy tylko fragment bez wypełnienia
        if (padVal == 8 && blocks.size() > 1) {
            // blok był w całości wypełniony
            blocks.remove(blocks.size() - 1);
        } else {
            byte[] trimmed = Arrays.copyOf(lastBlock, 8 - padVal);
            blocks.set(blocks.size() - 1, trimmed);
        }
    }
}

