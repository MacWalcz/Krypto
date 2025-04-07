package org.krypto.logic;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DES implements Cypher {

    class DESKeyException extends Exception { // Klasa do wyjątków klucza DES
        public DESKeyException(String message) {
            super(message);
        }
    }
    private String stringKey; // Klucz w formacie HEX
    private byte[] baseKey; // Podstawowy klucz 64-bitowy
    private byte[][] subkeys; // Tablica która przechowuje podklucze z każdej rundy
    private static final int BLOCK_SIZE = 8; // 64-bitowy blok
    private static final int KEY_SIZE = 8; // 64-bitowy klucz
    private static final int ROUNDS = 16; // Liczba rund dla algorytmu DES
    private static final byte[][][] S_BOXES = {
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
    
    private static final byte[] P_BLOCK = { // Permutacja do szyfrowania
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };

    private static final byte[] E_BLOCK = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
            };

    private static final byte[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final byte[] IP_INV = {
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
            setKeyHexx("133457799BBCDFF1"); // Konstruktor domyślny który wywołuję metodę setKeyHexx
        } catch (DESKeyException e) {
            e.printStackTrace();
        }
    }


    @Override
    public List<byte[]> encrypt(List<byte[]> blocks) { // Szyfrowanie wiadomości
        Padding.padMessage(blocks);
        List<byte[]> encryptedBlocks = new ArrayList<>(); // Lista na zaszyfrowane bloki

        for (byte[] block : blocks) { // Dla każdego bloku
            byte[] encryptedBlock = encryptBlock(block);// Szyfrowanie bloku
            encryptedBlocks.add(encryptedBlock); // Dodanie zaszyfrowanego bloku do listy
        }
        return encryptedBlocks;

    }

   @Override
    public List<byte[]> decrypt(List<byte[]> blocks) { // Odszyfrowanie wiadomości

        List<byte[]> decryptedBlocks = new ArrayList<>(); // Lista na odszyfrowane bloki

        for (byte[] block : blocks) { // Dla każdego bloku
            byte[] decryptedBlock = decryptBlock(block); // Odszyfrowanie bloku
            decryptedBlocks.add(decryptedBlock); // Dodanie odszyfrowanego bloku do listy
        }
        Padding.unpadMessage(decryptedBlocks);
        return decryptedBlocks;
    }

    public void setKeyHexx(String key) throws DESKeyException { // Zamiana klucza z stringa na HEX
        this.baseKey = new byte[KEY_SIZE]; // 64-bitowy klucz
        for (int i = 0; i < KEY_SIZE; i++) { // Zamiana klucza z HEX na bajty
            this.baseKey[i] = (byte) Integer.parseInt(key.substring(i * 2, i * 2 + 2), 16);
        }
        if (testKey()) { // Sprawdzamy czy warunki klucza są spełnione
            this.stringKey = key; // Jeśli tak to przypisujemy klucz
            subkeys = generateKeys(); // I gnerujemy podklucze
        }
    }

    public void setBaseKey(byte[] baseKey)  {
        this.baseKey = baseKey;
        this.subkeys = generateKeys();

    }

    public boolean testKey() throws DESKeyException { // Test klucza
        if (this.baseKey == null) {
            throw new DESKeyException("Klucz jest pusty!"); // Klucz nie może być pusty jak jest to DESKeyException
        }

        if(this.baseKey.length > KEY_SIZE) {
            throw new DESKeyException("Klucz jest za długi!"); // Klucz nie może być dłuższy niż 64 bity jak jest to DESKeyException
        }
        if(this.baseKey.length < KEY_SIZE) {
            throw new DESKeyException("Klucz jest za krótki!"); // Klucz nie może być krótszy niż 64 bity jak jest to DESKeyException
        }
        return true;
    }

    public byte[][] generateKeys() {

        final byte[] PC1 = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4}; // Permutacja klucza 64-bitowego
        final byte[] PC2 = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2}; // Permutacja klucza 56-bitowego
        final byte[] shifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}; // Liczba przesunięć w każdej rundzie

        byte[] C = new byte[4]; // Lewa połowa klucza
        byte[] D = new byte[4]; // Prawa połowa klucza
        byte[][] K = new byte[ROUNDS][]; // Tablica na podklucze

        byte[] key56 = permuteBytes(this.baseKey, PC1);
        

        for (int i = 0; i < 28; i++) {
            int bitVal = getBit(key56, i);
            setBit(C, i, bitVal);
        }
        for (int i = 28; i < 56; i++) {
            int bitVal = getBit(key56, i);
            setBit(D, i - 28, bitVal);
        }
        // Generowanie podkluczy dla 16 rund
        for (int i = 0; i < ROUNDS; i++) {
            // Przesunięcie w lewo bitów zgodnie z shifts
            C = leftShift(C, shifts[i],28);
            D = leftShift(D, shifts[i],28);
            // Złączenie obu połówek klucza
            // i permutacja do 48-bitowego klucza
            byte[] combinedKey = concatenate(C, D,28);
            K[i] = permuteBytes(combinedKey, PC2);
        }
        return K; // Zwróć tablicy z podkluczami
    }

    private byte[] leftShift(byte[] input, int n, int bitSize) {
        for (int i = 0; i < n; i++) {
            int firstBit = getBit(input, 0);
            for (int j = 0; j < bitSize - 1; j++) {
                int nextBit = getBit(input, j + 1);
                setBit(input, j, nextBit);
            }
            setBit(input, bitSize - 1, firstBit);
        }
        return input;
    }

    private byte[] permuteBytes(byte[] input, byte[] table) {
        byte[] output = new byte[(int) Math.ceil(table.length / 8.0)];
        for (int i = 0; i < table.length; i++) {
            int bit = getBit(input, table[i] - 1);
            setBit(output, i, bit);
        }
        return output;
    }
    private byte[] concatenate(byte[] a, byte[] b, int bitsEach) {
        int totalBits = bitsEach * 2; // 56
        byte[] result = new byte[(totalBits + 7) / 8]; // 56 bitów = 7 bajtów
        for (int i = 0; i < bitsEach; i++) {
            setBit(result, i, getBit(a, i));
            setBit(result, i + bitsEach, getBit(b, i));
        }
        return result;
    }

    private void setBit(byte[] data, int bitIndex, int value) {
        int byteIndex = bitIndex / 8;
        int bitPosition = 7 - (bitIndex % 8);
        if (value == 1) {
            data[byteIndex] |= (1 << bitPosition);
        } else {
            data[byteIndex] &= ~(1 << bitPosition);
        }
    }

    private int getBit(byte[] data, int bitIndex) {
        int byteIndex = bitIndex / 8;
        int bitPos = 7 - (bitIndex % 8);
        return (data[byteIndex] >> bitPos) & 1;
    }

    private byte[] XORBytes(byte[] a, byte[] b) { // Funkcja do XORowania dwóch tablic bajtów
        byte[] result = new byte[Math.max(a.length, b.length)];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    private byte[] sBoxSubstitution(byte[] input) {
        byte[] output = new byte[4];
        for (int i = 0; i < 8; i++) {
            int offset = i * 6;
            int row = (getBit(input, offset) << 1) | getBit(input, offset + 5);
            int col = (getBit(input, offset + 1) << 3)
                    | (getBit(input, offset + 2) << 2)
                    | (getBit(input, offset + 3) << 1)
                    | getBit(input, offset + 4);
            int sboxVal = S_BOXES[i][row][col];
            for (int j = 0; j < 4; j++) {
                setBit(output, i * 4 + j, (sboxVal >> (3 - j)) & 1);
            }
        }
        return output;
    }

    private byte[] feistelFunction(byte[] R, byte[] subkey) {
        byte[] expanded = permuteBytes(R, E_BLOCK); // 48 bits
        byte[] xored = XORBytes(expanded, subkey);
        byte[] sboxOutput = sBoxSubstitution(xored);
        return permuteBytes(sboxOutput, P_BLOCK); // 32 bits
    }

    public byte[] encryptBlock(byte[] block) {
        byte[] permutedBlock = permuteBytes(block, IP); // 64->64
        byte[] L = Arrays.copyOfRange(permutedBlock, 0, 4);  // 4 bajty => 32 bitów
        byte[] R = Arrays.copyOfRange(permutedBlock, 4, 8);

        for (int i = 0; i < 16; i++) {
            byte[] temp = R;
            R = XORBytes(L, feistelFunction(R, subkeys[i]));
            L = temp;
        }
        byte[] combined = concatenate(R, L, 32);
        return permuteBytes(combined, IP_INV);
    }

    public byte[] decryptBlock(byte[] block) {
        byte[] permutedBlock = permuteBytes(block, IP);
        byte[] L = Arrays.copyOfRange(permutedBlock, 0, 4);
        byte[] R = Arrays.copyOfRange(permutedBlock, 4, 8);

        for (int i = 15; i >= 0; i--) {
            byte[] temp = R;
            R = XORBytes(L, feistelFunction(R, subkeys[i]));
            L = temp;
        }

        byte[] combined = concatenate(R, L, 32);
        return permuteBytes(combined, IP_INV);
    }
}




