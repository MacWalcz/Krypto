package org.krypto.logic;

public interface Cypher {
    public void encrypt(byte[] message);
    public void decrypt(byte[] message);
}
