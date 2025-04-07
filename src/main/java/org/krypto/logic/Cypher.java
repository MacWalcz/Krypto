package org.krypto.logic;

public interface Cypher {
    public void encrypt(String inputFile, String outputFile);
    public void decrypt(String inputFile, String outputFile);
}
