package org.krypto.logic;

public class DES implements Cypher {

    class DESKeyException extends Exception {
        public DESKeyException(String message) {
            super(message);
        }
    }

    private String stringKey;
    private byte[] baseKey; // 64-bit key
    private byte[][] subkeys; // Subkeys for each round
    private static final int BLOCK_SIZE = 8; // 64 bits
    private static final int KEY_SIZE = 8; // 64 bits
    private static final int ROUNDS = 16; // Number of rounds for DES
    private static final byte[] S_BOX =  {
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
    
    private static final byte[] P_BLOCK = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };

    DES(){
        try {
            setKeyHexx("0123456789ABCDEF");
        } catch (DESKeyException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void encrypt(byte[] message ) {
        throw new UnsupportedOperationException("Not supported yet.");

    }

    @Override
    public void decrypt(byte[] message) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setKeyString(String key) throws Exception {
        this.baseKey = key.getBytes("UTF-16BE");

        if (testKey()) {
            this.stringKey = key;
            subkeys = generateKeys(); 
        }
    }

    public void setKeyHexx(String key) throws DESKeyException {
        this.baseKey = new byte[KEY_SIZE];
        for (int i = 0; i < KEY_SIZE; i++) {
            this.baseKey[i] = (byte) Integer.parseInt(key.substring(i * 2, i * 2 + 2), 16);
        }
        if (testKey()) {
            this.stringKey = key;
            subkeys = generateKeys(); 
        }
    }

    public boolean testKey() throws DESKeyException {
        if (this.baseKey == null) {
            throw new DESKeyException("Klucz jest pusty!");
        }

        if(this.baseKey.length > KEY_SIZE) {
            throw new DESKeyException("Klucz jest za długi!");
        }
        if(this.baseKey.length < KEY_SIZE) {
            throw new DESKeyException("Klucz jest za krótki!");
        }
        return true;
    }

    public byte[][] generateKeys() {

        final byte[] PC1 = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
        final byte[] PC2 = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2};
        final byte[] shifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

        byte[] key = new byte[KEY_SIZE]; // 64-bit key
        byte[] C = new byte[28]; // Left half of the key
        byte[] D = new byte[28]; // Right half of the key
        byte[][] K = new byte[ROUNDS][]; // Subkeys for each round 

        permute(key, PC1);

        byte[] key56 = new byte[56]; // 56-bit key after PC1
        for (int i = 0; i < 56; i++) {
            key56[i] = key[PC1[i] - 1];
        }
        // Split the key into two halves
        System.arraycopy(key56, 0, C, 0, 28);
        System.arraycopy(key56, 28, D, 0, 28);
        
        // Generate subkeys for each round
        for (int i = 0; i < ROUNDS; i++) {
            // Perform left shifts
            C = leftShift(C, shifts[i]);
            D = leftShift(D, shifts[i]);
            // Combine C and D into K
            byte[] combinedKey = concatenate(C, D);
            K[i] = permute(combinedKey, PC2); 
        }
        return K; // Return the last subkey for demonstration purposes

    }

    private byte[] leftShift(byte[] halfKey, int shifts) {
        byte[] shiftedKey = new byte[halfKey.length];
        for (int i = 0; i < halfKey.length; i++) {
            shiftedKey[i] = halfKey[(i + shifts) % halfKey.length];
        }
        return shiftedKey;
    }

    private byte[] permute(byte[] block, byte[] permutation) {
        byte[] permutedBlock = new byte[block.length];
        for (int i = 0; i < permutation.length; i++) {
            permutedBlock[i] = block[permutation[i] - 1];
        }
        return permutedBlock;
    }

    private byte[] concatenate(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }

    
    
}
