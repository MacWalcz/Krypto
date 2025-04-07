package org.krypto.logic;

import java.security.SecureRandom;

public class Generator {
    public static byte[][] generate8ByteKeys(int count) {
        SecureRandom random = new SecureRandom();
        byte[][] keys = new byte[count][8]; // każdy klucz ma 8 bajtów

        for (int i = 0; i < count; i++) {
            random.nextBytes(keys[i]); // wypełnia 8 bajtów losowymi wartościami
        }

        return keys;
    }
}
