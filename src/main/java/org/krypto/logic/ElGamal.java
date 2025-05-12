package org.krypto.logic;

import java.util.*;
import java.security.SecureRandom;
import java.math.BigInteger;
import org.krypto.logic.Converter;

public class ElGamal {

    private BigInteger[] pubKey;  //(p,g,e) gdzie p - losowa wielka liczba pierwsza
    // g - pierwiastek pierwotny p
    // e - g^a mod p
    private BigInteger privKey;   //a - losowy int przy generowaniu kluczy
    private final int keyLength = 512; //długość klucza w bitach, giga duże wiadomości można
    private final SecureRandom random = new SecureRandom();


    private BigInteger generateSafePrime(int bitLength) {
        while (true) {
            BigInteger q = BigInteger.probablePrime(bitLength - 1, random);
            BigInteger p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
            if (p.isProbablePrime(20)) {
                return p;
            }
        }
    }

    private static List<BigInteger> primeFactors(BigInteger n) {
        List<BigInteger> factors = new ArrayList<>();

        while (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            factors.add(BigInteger.TWO);
            n = n.divide(BigInteger.TWO);
        }

        BigInteger i = BigInteger.valueOf(3);
        while (i.multiply(i).compareTo(n) <= 0) {
            while (n.mod(i).equals(BigInteger.ZERO)) {
                factors.add(i);
                n = n.divide(i);
            }
            i = i.add(BigInteger.TWO);
        }

        if (n.compareTo(BigInteger.ONE) > 0) {
            factors.add(n);
        }

        return factors;
    }


    private BigInteger findPrimitiveRoot(BigInteger p) {
        if (!p.isProbablePrime(20)) {
            throw new IllegalArgumentException("Liczba p musi być pierwsza.");
        }

        BigInteger phi = p.subtract(BigInteger.ONE);
        BigInteger q = phi.divide(BigInteger.TWO);
        Set<BigInteger> uniqueFactors = Set.of(BigInteger.TWO, q);

        for (BigInteger g = new BigInteger(p.bitLength(), random).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO); g.compareTo(p) < 0; g = new BigInteger(p.bitLength(), random).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO)) {
            boolean isPrimitiveRoot = true;
            for (BigInteger uf : uniqueFactors) {
                BigInteger pow = phi.divide(uf);
                if (g.modPow(pow, p).equals(BigInteger.ONE)) {
                    isPrimitiveRoot = false;
                    break;
                }
            }
            if (isPrimitiveRoot) {
                return g;
            }
        }

        return BigInteger.valueOf(-1); // Nie znaleziono (nie powinno się zdarzyć)
    }



    public ElGamal() {
        this.generateKeys();
    }


    public void generateKeys() {
        BigInteger p = generateSafePrime(keyLength);
        BigInteger g = findPrimitiveRoot(p);
        while (g.equals(BigInteger.ZERO)) {
            p.nextProbablePrime();
            g = findPrimitiveRoot(p);
        }
        BigInteger a = new BigInteger(keyLength, random);
        while (a.compareTo(BigInteger.ONE) <= 0) {
            a = new BigInteger(keyLength, random);
        }
        BigInteger e = g.modPow(a, p);
        pubKey = new BigInteger[]{p, g, e};
        privKey = a;
    }

    public List<BigInteger[]> encrypt(List<byte[]> message) {
        List<BigInteger[]> ciphertext = new ArrayList<>();

        for (byte[] block : message) {
            BigInteger b = new BigInteger(keyLength, random);
            while (b.compareTo(BigInteger.ONE) <= 0) {
                b = new BigInteger(keyLength, random);
            }
            BigInteger m = Converter.toUnsignedBigInteger(block);
            ciphertext.add(new BigInteger[]{pubKey[1].modPow(b, pubKey[0]), m.multiply(pubKey[2].modPow(b, pubKey[0])).mod(pubKey[0])}); //C1 to [0] C2 to [1]
        }
        return ciphertext;
    }

    public List<byte[]> decrypt(List<BigInteger[]> ciphertext) {
        List<byte[]> decryptedmessage = new ArrayList<>();
        for (BigInteger[] block : ciphertext) {
            BigInteger x = block[0].modPow(privKey, pubKey[0]);
            decryptedmessage.add(Converter.fromUnsignedBigInteger(block[1].multiply(x.modPow(pubKey[0].subtract(BigInteger.TWO), pubKey[0])).mod(pubKey[0]),63));
        }
        return decryptedmessage;
    }

    public BigInteger[] getPubKey() {
        return pubKey;
    }

    public void setPubKey(BigInteger[] pubKey) {
        this.pubKey = pubKey;
    }

    public BigInteger getPrivKey() {
        return privKey;
    }

    public void setPrivKey(BigInteger privKey) {
        this.privKey = privKey;
    }
}
