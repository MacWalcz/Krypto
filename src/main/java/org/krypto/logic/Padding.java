package org.krypto.logic;

import java.util.Arrays;
import java.util.List;

public class Padding {
    public static void padMessage(List<byte[]> blocks, int blockSize) {
        if (blocks.isEmpty()) return;
        byte[] last = blocks.get(blocks.size()-1);
        int padCount = blockSize - last.length;
        if (padCount == 0) return;
        byte[] nb = Arrays.copyOf(last, blockSize);
        for (int i = blockSize - padCount; i < blockSize; i++) nb[i] = (byte) padCount;
        blocks.set(blocks.size()-1, nb);
    }

    public static void unpadMessage(List<byte[]> blocks, int blockSize) {
        if (blocks.isEmpty()) return;
        byte[] last = blocks.get(blocks.size()-1);
        if (last.length != blockSize) return;
        int padVal = last[blockSize-1] & 0xFF;
        if (padVal < 1 || padVal >= blockSize) return;
        for (int i = blockSize - padVal; i < blockSize; i++) {
            if ((last[i] & 0xFF) != padVal) return;
        }
        blocks.set(blocks.size()-1, Arrays.copyOf(last, blockSize - padVal));
    }
}