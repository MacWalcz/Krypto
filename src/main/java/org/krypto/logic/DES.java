package org.krypto.logic;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DES implements Cypher {

    class DESKeyException extends Exception {
        public DESKeyException(String message) {
            super(message);
        }
    }

    private String stringKey; // Klucz w formacie HEX
    private byte[] baseKey;   // Podstawowy klucz 64-bitowy
    private byte[][] subkeys; // Tablica która przechowuje podklucze z każdej rundy
    private static final int BLOCK_SIZE = 8; // 64-bitowy blok
    private static final int KEY_SIZE = 8;   // 64-bitowy klucz
    private static final int ROUNDS = 16;    // Liczba rund dla algorytmu DES

    private static final byte[][][] S_BOXES = { // S-boxy
            { // S1
                    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
            },
            { // S2
                    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
            },
            { // S3
                    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
            },
            { // S4
                    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
            },
            { // S5
                    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
            },
            { // S6
                    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
            },
            { // S7
                    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
            },
            { // S8
                    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
            }
    };

    private static final byte[] P_BLOCK = { // Tablica P do permutacji
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    private static final byte[] E_BLOCK = { // Tablica E do rozszerzenia
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    private static final byte[] IP = { // Tablica initial Permutation do permutacji
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final byte[] IP_INV = { // Tablica odwrotnej permutacji
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    public DES(){
        try {
            setKeyHexx("0123456789ABCDEF"); // Konstruktor domyślny
        } catch (DESKeyException e) {
            e.printStackTrace();
        }
    }

    @Override
    public List<byte[]> encrypt(List<byte[]> blocks) { // Kodowanie bloków
        Padding.padMessage(blocks); // Dodawanie paddingu do wiadomości żeby była wielokrotnością 8 bajtów
        List<byte[]> encryptedBlocks = new ArrayList<>();
        for (byte[] block : blocks) {
            byte[] encryptedBlock = encryptBlock(block);
            encryptedBlocks.add(encryptedBlock);
        }
        return encryptedBlocks;
    }

    @Override
    public List<byte[]> decrypt(List<byte[]> blocks) { // Dekodowanie bloków
        List<byte[]> decryptedBlocks = new ArrayList<>();
        for (byte[] block : blocks) {
            byte[] decryptedBlock = decryptBlock(block);
            decryptedBlocks.add(decryptedBlock);
        }
        Padding.unpadMessage(decryptedBlocks); // Usuwanie paddingu z wiadomości aby uniknąć zbędnych zerowych bajtów
        return decryptedBlocks;
    }

    public void setKeyHexx(String key) throws DESKeyException { // Funkcja do ustawiania klucza w formacie HEX
        this.baseKey = new byte[KEY_SIZE]; // Tworzymy nową tablicę bajtów o długości 8 bajtów (64 bity)
        for (int i = 0; i < KEY_SIZE; i++) {
            this.baseKey[i] = (byte) Integer.parseInt(key.substring(i * 2, i * 2 + 2), 16); // Konwertujemy klucz z formatu HEX na bajty
        }
        if (testKey()) { // Sprawdzamy warunki poprawności klucza
            this.stringKey = key; // Jeśli klucz jest poprawny to przypisujemy go do zmiennej stringKey
            subkeys = generateKeys(); // I generujemy podklucze 
        }
    }

    public void setBaseKey(byte[] baseKey) throws DESKeyException { // Funkcja do ustawiania baseKey w formacie byte[]
        if(testKey()) { // Sprawdzamy warunki poprawności klucza
            this.baseKey = baseKey; // Jeśli klucz jest poprawny to przypisujemy go do zmiennej baseKey
            this.subkeys = generateKeys(); // I generujemy podklucze
        }
    }

    private boolean testKey() throws DESKeyException { // Funkcja testująca warunki klucza
        if (this.baseKey == null) { // Klucz nie może być pusty
            throw new DESKeyException("Klucz jest pusty!"); // Jeśli klucz jest pusty, to wyrzucamy wyjątek
        }
        if(this.baseKey.length != KEY_SIZE) { // Klucz musi mieć dokładnie 8 bajtów
            throw new DESKeyException("Klucz musi mieć 8 bajtów!"); // Jeśli klucz nie ma 8 bajtów, to wyrzucamy wyjątek
        }
        return true; // Jak wszystko się zgadza to zwracamy true
    }

    private byte[][] generateKeys() { // Funkcja generująca 16 podkluczy
        
        final byte[] PC1 = {
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
        };                                  // PC1 - Permutacja klucza 64bit->56bit
                                            // PC2 - Permutacja klucza 56bit->48bit
        final byte[] PC2 = {
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
        };
        final byte[] shifts = { // Liczba przesunięć w każdej rundzie
                1, 1, 2, 2, 2, 2, 2, 2,
                1, 2, 2, 2, 2, 2, 2, 1
        };

        byte[][] K = new byte[ROUNDS][]; // 16 podkluczy (w każdej rundzie jeden)

        byte[] key56 = permuteBytes(this.baseKey, PC1); // Permutacja klucza 64bit->56bit

        // Podział klucza 56bit na 2 częsci 28bitowe
        byte[] C = new byte[4]; 
        byte[] D = new byte[4];
        for (int i = 0; i < 28; i++) {
            setBit(C, i, getBit(key56, i));
        }
        for (int i = 28; i < 56; i++) {
            setBit(D, i - 28, getBit(key56, i));
        }
        
        // Generowanie 16 podkluczy
        // W każdej rundzie przesuwamy C i D o n (zależne dla i-tej rundy od shifts[i]) bitów, a następnie wykonujemy permutację PC2
        for (int i = 0; i < ROUNDS; i++) {
            C = leftShift(C, shifts[i], 28);
            D = leftShift(D, shifts[i], 28);
            byte[] CD = concatenate(C, D, 28); // Złączenie 2 części klucza w całość 56bitową
            K[i] = permuteBytes(CD, PC2); // Permutacja klucza 56bit->48bit
        }
        return K; // Zwracamy tablicę 16 podkluczy
    }

    private byte[] leftShift(byte[] data, int n, int usedBits) {   // Przesunięcie bitów w lewo o n bitów w tablicy data o długości usedBits                                                 
        for (int i = 0; i < n; i++) {                              // usedBits aby pomóc w nieprzekraczaniu długości tablicy
            int firstBit = getBit(data, 0); // bierzemy pierwszy bit
            for (int j = 0; j < usedBits - 1; j++) { // przesuwamy bity w lewo
                setBit(data, j, getBit(data, j + 1)); 
            }
            setBit(data, usedBits - 1, firstBit); // ostatni bit ustawiamy na pierwszy bit
        }
        return data; // zwracamy przesuniętą tablicę
    }

    private byte[] concatenate(byte[] a, byte[] b, int bitsEach) { // Łączenie dwóch tablic bajtów a i b (głownie do podkluczy)
        int totalBits = bitsEach * 2; // Dwie tablice mają po tyle samo bitów więc łącząc ich w jedną musimy pomnożyć razy 2
        byte[] result = new byte[(totalBits + 7)/8]; // Dzielimy przez 8 aby uzyskać liczbę bajtów, a następnie zaokrąglamy w górę
        for (int i = 0; i < bitsEach; i++) { 
            setBit(result, i, getBit(a, i)); // Ustawiamy bity z tablicy a w nowej tablicy result
            setBit(result, i + bitsEach, getBit(b, i)); // Ustawiamy bity z tablicy b w nowej tablicy result
        }
        return result;
    }

    private byte[] permuteBytes(byte[] input, byte[] table) { // Funkcja do permutacji bajtów
        byte[] output = new byte[(int) Math.ceil(table.length/8.0)]; // Tworzymy nową tablicę bajtów o długości równej długości tablicy permutacyjnej dzielimy przez 8 i zaokrąglamy w górę 
        for (int i = 0; i < table.length; i++) {
            int bit = getBit(input, table[i] - 1); // Pobieramy bit z tablicy wejściowej na podstawie wartości w tablicy permutacyjnej
            setBit(output, i, bit); // Ustawiamy bit w nowej tablicy wyjściowej na podstawie wartości w tablicy permutacyjnej
        }
        return output; // Zwracamy nową tablicę bajtów
    }

    private int getBit(byte[] data, int bitIndex) { // Funkcja do pobierania konkretnego bitu z tablicy bajtów
        int byteIndex = bitIndex / 8; // Obliczamy indeks bajtu na podstawie indeksu bitu
        int bitPos = 7 - (bitIndex % 8); // Obliczamy pozycję bitu w bajcie (od końca bajtu)

        return (data[byteIndex] >> bitPos) & 1; // Przesuwamy bajt o bitPos w prawo i maskujemy z 1 aby uzyskać wartość bitu
    }

    private void setBit(byte[] data, int bitIndex, int value) { // Funkcja do ustawiania wartośći konkretnego bitu w tablicy bajtów
        int byteIndex = bitIndex / 8;
        int bitPos = 7 - (bitIndex % 8);
        if (value == 1) { // Jeśli value = 1 to ustawiamy bit na 1
            data[byteIndex] |= (1 << bitPos);
        } else { // Jeśli nie to negujemy bit
            data[byteIndex] &= ~(1 << bitPos);
        }
    }

    private byte[] XORBytes(byte[] a, byte[] b) { // Funkcja do wykonywania operacji XOR na dwóch tablicach bajtów
        if (a.length != b.length) { // Sprawdzamy czy długości tablic są równe
            throw new IllegalArgumentException("Tablice muszą mieć tę samą długość!"); // Jeśli nie to wyrzucamy wyjątek
        }
        byte[] result = new byte[a.length]; // Tworzymy nową tablicę bajtów o długości równej długości tablicy a
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte)(a[i] ^ b[i]); // Wykonujemy operację XOR na każdym bajcie tablicy a i b i zapisujemy wynik w nowej tablicy result
        }
        return result; // Zwracamy nową tablicę bajtów po operacji XOR
    }

    private byte[] sBoxSubstitution(byte[] input) { // Funkcja do podstawienia S-boxów
        byte[] output = new byte[4];  // Tworzymy nową tablicę bajtów o długości 4 bajtów (32 bity)
        for (int i = 0; i < 8; i++) { // Iterujemy po 8 S-boxach
            int offset = i * 6; // Obliczamy offset dla każdego S-boxa
            int row = (getBit(input, offset) << 1) | getBit(input, offset+5); // Pobieramy wiersz z S-boxa
            int col = (getBit(input, offset+1) << 3) | // Pobieramy kolumnę z S-boxa
                    (getBit(input, offset+2) << 2) | // Przesuwamy bity w lewo aby uzyskać odpowiednią wartość
                    (getBit(input, offset+3) << 1) | 
                    getBit(input, offset+4); 
            int sboxVal = S_BOXES[i][row][col]; // Pobieramy wartość z S-boxa na podstawie wiersza i kolumny
            for (int j = 0; j < 4; j++) { // Iterujemy po 4 bitach w S-boxie
                setBit(output, i*4 + j, (sboxVal >> (3-j)) & 1); // Ustawiamy bity w nowej tablicy wyjściowej na podstawie wartości z S-boxa
            }
        }
        return output; // Zwracamy nową tablicę bajtów po podstawieniu S-boxów
    }

    private byte[] feistelFunction(byte[] R, byte[] subkey) { // Funkcja Feistela
        // R=32->48, XOR, S-box=32, P=32
        byte[] expanded = permuteBytes(R, E_BLOCK); // Rozszerzamy 32 bity na 48 bitów
        byte[] xored = XORBytes(expanded, subkey); // Wykonujemy operację XOR z podkluczem
        byte[] sboxOut = sBoxSubstitution(xored); // Podstawiamy S-boxy

        return permuteBytes(sboxOut, P_BLOCK); // Wykonujemy permutację na podstawie wartości z S-boxów
    }

    public byte[] encryptBlock(byte[] block) { // Funkcja do szyfrowania bloku 64-bitowego
        byte[] perm = permuteBytes(block, IP); // Permutacja bloku 64-bitowego
        byte[] L = Arrays.copyOfRange(perm, 0, 4); // Dzielimy blok na 2 części 32-bitowe
        byte[] R = Arrays.copyOfRange(perm, 4, 8);
        for(int i=0; i<16; i++) {
            byte[] temp = R; // Zmienna pomocnicza do przechowywania wartości R
            R = XORBytes(L, feistelFunction(R, subkeys[i])); // Wykonujemy operację XOR z funkcją Feistela
            L = temp; // Przypisujemy wartość R do L
        }
        byte[] combined = concatenate(R, L, 32); // Łączymy 2 części bloku w jedną całość 64-bitową
        return permuteBytes(combined, IP_INV); // Wykonujemy odwrotną permutację na podstawie wartości z bloku
    }

    public byte[] decryptBlock(byte[] block) { // Funkcja do deszyfrowania bloku 64-bitowego
        byte[] perm = permuteBytes(block, IP); // Permutacja bloku 64-bitowego
        byte[] L = Arrays.copyOfRange(perm, 0, 4); // Dzielimy blok na 2 części 32-bitowe
        byte[] R = Arrays.copyOfRange(perm, 4, 8);
        for(int i=15; i>=0; i--) {
            byte[] temp = R; // Zmienna pomocnicza do przechowywania wartości R
            R = XORBytes(L, feistelFunction(R, subkeys[i])); // Wykonujemy operację XOR z funkcją Feistela
            L = temp; // Przypisujemy wartość R do L
        }
        byte[] combined = concatenate(R, L, 32); // Łączymy 2 części bloku w jedną całość 64-bitową
        return permuteBytes(combined, IP_INV); // Wykonujemy odwrotną permutację na podstawie wartości z bloku
    }
}
