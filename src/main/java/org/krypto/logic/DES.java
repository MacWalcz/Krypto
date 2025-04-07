package org.krypto.logic;

import java.util.ArrayList;
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
    private static final byte[] S_BOX =  { // tablica S-box
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, // S1
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,   
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, // S2
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, // S3
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, // S4
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, // S5
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, // S6
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, // S7
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, // S8
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
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

    public DES(){
        try {
            setKeyHexx("0123456789ABCDEF"); // Konstruktor domyślny który wywołuję metodę setKeyHexx
        } catch (DESKeyException e) {
            e.printStackTrace();
        }
    }


    @Override
    public void encrypt(String inputFile, String outputFile) { // Szyfrowanie wiadomości
        List<byte[]> blocks = FileDao.read(inputFile); // Odczytanie pliku z wiadomością
        List<byte[]> encryptedBlocks = new ArrayList<>(); // Lista na zaszyfrowane bloki

        for (byte[] block : blocks) { // Dla każdego bloku
            byte[] encryptedBlock = encryptBlock(block); // Szyfrowanie bloku
            encryptedBlocks.add(encryptedBlock); // Dodanie zaszyfrowanego bloku do listy
        }
        FileDao.write(encryptedBlocks, outputFile); // Zapisanie zaszyfrowanych bloków do pliku

    }

   @Override
    public void decrypt(String inputFile, String outputFile) { // Odszyfrowanie wiadomości
        List<byte[]> blocks = FileDao.read(inputFile); // Odczytanie pliku z wiadomością
        List<byte[]> decryptedBlocks = new ArrayList<>(); // Lista na odszyfrowane bloki

        for (byte[] block : blocks) { // Dla każdego bloku
            byte[] decryptedBlock = decryptBlock(block); // Odszyfrowanie bloku
            decryptedBlocks.add(decryptedBlock); // Dodanie odszyfrowanego bloku do listy
        }
        FileDao.write(decryptedBlocks,outputFile); // Zapisanie odszyfrowanych bloków do pliku
    }

    public void setKeyString(String key) throws Exception { // Zamiana klucza z stringa na bajty
        this.baseKey = key.getBytes("UTF-16BE");

        if (testKey()) { // Sprawdzamy czy warunki klucza są spełnione
            this.stringKey = key; // Jeśli tak to przypisujemy klucz
            subkeys = generateKeys(); // I gnerujemy podklucze
        }
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

        byte[] C = new byte[28]; // Lewa połowa klucza
        byte[] D = new byte[28]; // Prawa połowa klucza
        byte[][] K = new byte[ROUNDS][]; // Tablica na podklucze

        byte[] key56 = permuteBits(this.baseKey, PC1);
        
        // Rozdzielenie klucza na dwie 28-bitowe części
        System.arraycopy(key56, 0, C, 0, 28);
        System.arraycopy(key56, 28, D, 0, 28);
        
        // Generate subkeys for each round
        for (int i = 0; i < ROUNDS; i++) {
            // Perform left shifts
            C = leftShift(C, shifts[i]);
            D = leftShift(D, shifts[i]);
            // Złączenie obu połówek klucza
            // i permutacja do 48-bitowego klucza
            byte[] combinedKey = concatenate(C, D);
            K[i] = permuteBits(combinedKey, PC2); 
        }
        return K; // Zwróć tablicy z podkluczami
    }

    private byte[] leftShift(byte[] halfKey, int shifts) {
        byte[] shiftedKey = new byte[halfKey.length];
        for (int i = 0; i < halfKey.length; i++) {
            int newBitPos = (i + shifts) % halfKey.length; // Nowa pozycja bitu
            
            int oldBytePos = i / 8;
            int oldBitPos = i % 8;
    
            int bit = (halfKey[oldBytePos] >> (7 - oldBitPos)) & 1;
            
            int newBytePos = newBitPos / 8;
            int newBitPosInByte = 7 - (newBitPos % 8);
            
            shiftedKey[newBytePos] |= (bit << newBitPosInByte);
        }
    
        return shiftedKey;
    }
    
    private byte[] permuteBits(byte[] block, byte[] permutation) {
        byte[] result = new byte[permutation.length];
        for (int i = 0; i < permutation.length; i++) {
            int bit = getBit(block, permutation[i] - 1);
            result[i] = (byte) bit;
        }
        return result;
    }
    
    private byte[] concatenate(byte[] left, byte[] right) { // Funkcja do łączenia dwóch tablic bajtów
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);

        return result;
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

    private byte[] SBoxSubstitution(byte[] input) { // Funkcja do podstawienia S-box
        byte[] output = new byte[4]; // 32 bity wyjścia
        for (int i = 0; i < 8; i++) {
            int row = ((input[i * 6] & 0x01) << 1) | ((input[i * 6 + 5] & 0x01)); // Wiersz S-box
            int col = ((input[i * 6 + 1] & 0x01) << 3) | ((input[i * 6 + 2] & 0x01) << 2) | ((input[i * 6 + 3] & 0x01) << 1) | (input[i * 6 + 4] & 0x01); // Kolumna S-box
            int sValue = S_BOX[row * 16 + col]; // Wartość z S-box
            output[i / 2] |= (sValue << (4 * (1 - (i % 2)))); // Podstawienie do wyjścia
        }
        return output;
    }

    private byte[] feistelFunction(byte[] right, byte[] subkey) { // Funkcja Feistela
        byte[] expandedRight = new byte[6]; // Rozszerzenie prawej części
        for (int i = 0; i < 48; i++) {
            expandedRight[i] = right[P_BLOCK[i] - 1]; // Rozszerzenie do 48 bitów
        }
        byte[] xorResult = XORBytes(expandedRight, subkey); // XOR z podkluczem
        byte[] sBoxOutput = SBoxSubstitution(xorResult); // Podstawienie S-box
        byte[] permutedOutput = permuteBits(sBoxOutput, P_BLOCK); // Permutacja P-block

        return permutedOutput;
    }

    private byte[] initialPermutation(byte[] block) { // Inicjalna permutacja
        byte[] permutedBlock = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            permutedBlock[i] = block[P_BLOCK[i] - 1]; // Permutacja do 64 bitów
        }
        return permutedBlock;
    }

    private byte[] inverseInitialPermutation(byte[] block) { // Odwrócona inicjalna permutacja
        byte[] permutedBlock = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            permutedBlock[P_BLOCK[i] - 1] = block[i]; // Permutacja do 64 bitów
        }
        return permutedBlock;
    }

    private byte[] encryptBlock(byte[] block) { // Szyfrowanie bloku
        byte[] permutedBlock = initialPermutation(block); // Inicjalna permutacja
        byte[] left = new byte[32]; // Lewa część bloku
        byte[] right = new byte[32]; // Prawa część bloku

        System.arraycopy(permutedBlock, 0, left, 0, 32); // Lewa część bloku
        System.arraycopy(permutedBlock, 32, right, 0, 32); // Prawa część bloku

        for (int i = 0; i < ROUNDS; i++) {
            byte[] temp = right; // Tymczasowa zmienna do przechowywania prawej części
            right = XORBytes(left, feistelFunction(right, subkeys[i])); // XOR z funkcją Feistela
            left = temp; // Lewa część bloku
        }
        byte[] combinedBlock = concatenate(left, right); // Połączenie obu części bloku

        return inverseInitialPermutation(combinedBlock); // Odwrócona inicjalna permutacja
    }

    private byte[] decryptBlock(byte[] block) { // Odszyfrowanie bloku
        byte[] permutedBlock = initialPermutation(block); // Inicjalna permutacja
        byte[] left = new byte[32]; // Lewa część bloku
        byte[] right = new byte[32]; // Prawa część bloku

        System.arraycopy(permutedBlock, 0, left, 0, 32); // Lewa część bloku
        System.arraycopy(permutedBlock, 32, right, 0, 32); // Prawa część bloku

        for (int i = ROUNDS - 1; i >= 0; i--) {
            byte[] temp = right; // Tymczasowa zmienna do przechowywania prawej części
            right = XORBytes(left, feistelFunction(right, subkeys[i])); // XOR z funkcją Feistela
            left = temp; // Lewa część bloku
        }
        byte[] combinedBlock = concatenate(left, right); // Połączenie obu części bloku

        return inverseInitialPermutation(combinedBlock); // Odwrócona inicjalna permutacja
    }

    private byte[] padMessage(byte[] message) { // Padding wiadomości do 64 bitów
        int paddingLength = BLOCK_SIZE - (message.length % BLOCK_SIZE); // Długość paddingu
        byte[] paddedMessage = new byte[message.length + paddingLength]; // Tablica na wiadomość z paddingiem
        System.arraycopy(message, 0, paddedMessage, 0, message.length); // Skopiowanie wiadomości do tablicy z paddingiem
        for (int i = message.length; i < paddedMessage.length; i++) {
            paddedMessage[i] = (byte) paddingLength; // Dodanie paddingu
        }
        return paddedMessage;
    }

    private byte[] unpadMessage(byte[] message) { // Usunięcie paddingu z wiadomości
        int paddingLength = message[message.length - 1]; // Długość paddingu
        byte[] unpaddedMessage = new byte[message.length - paddingLength]; // Tablica na wiadomość bez paddingu
        System.arraycopy(message, 0, unpaddedMessage, 0, unpaddedMessage.length); // Skopiowanie wiadomości do tablicy bez paddingu

        return unpaddedMessage; // Zwrócenie wiadomości bez paddingu
    }

    private byte[] encryptMessage(byte[] message) { // Szyfrowanie wiadomości
        byte[] paddedMessage = padMessage(message); // Padding wiadomości
        byte[] encryptedMessage = new byte[paddedMessage.length]; // Tablica na zaszyfrowaną wiadomość

        for (int i = 0; i < paddedMessage.length; i += BLOCK_SIZE) {
            byte[] block = new byte[BLOCK_SIZE]; // Blok do szyfrowania
            System.arraycopy(paddedMessage, i, block, 0, BLOCK_SIZE); // Skopiowanie bloku do tablicy
            byte[] encryptedBlock = encryptBlock(block); // Szyfrowanie bloku
            System.arraycopy(encryptedBlock, 0, encryptedMessage, i, BLOCK_SIZE); // Skopiowanie zaszyfrowanego bloku do tablicy
        }
        return encryptedMessage; // Zwrócenie zaszyfrowanej wiadomości
    }
    private byte[] decryptMessage(byte[] message) { // Odszyfrowanie wiadomości
        byte[] decryptedMessage = new byte[message.length]; // Tablica na odszyfrowaną wiadomość

        for (int i = 0; i < message.length; i += BLOCK_SIZE) {
            byte[] block = new byte[BLOCK_SIZE]; // Blok do odszyfrowania
            System.arraycopy(message, i, block, 0, BLOCK_SIZE); // Skopiowanie bloku do tablicy
            byte[] decryptedBlock = decryptBlock(block); // Odszyfrowanie bloku
            System.arraycopy(decryptedBlock, 0, decryptedMessage, i, BLOCK_SIZE); // Skopiowanie odszyfrowanego bloku do tablicy
        }
        return unpadMessage(decryptedMessage); // Zwrócenie odszyfrowanej wiadomości bez paddingu
    }
    
}
