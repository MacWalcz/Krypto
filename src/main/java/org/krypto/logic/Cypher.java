package org.krypto.logic;

import java.util.List;

public interface Cypher {
    public List<byte[]> encrypt(List<byte[]> data);
    public List<byte[]> decrypt(List<byte[]> data);
}
