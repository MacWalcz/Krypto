package org.krypto.logic;


import java.util.List;

public class Padding {

    public static void padMessage(List<byte[]> message) { // Padding wiadomości do 64 bitów


        byte[] lastBlock = message.get(message.size() - 1);
        int paddingLength = 8 - lastBlock.length;

        // Jeśli blok niepełny, dopełniamy zerami do 8 bajtów
        if (paddingLength > 0) {
            byte[] paddedBlock = new byte[8];
            System.arraycopy(lastBlock, 0, paddedBlock, 0, lastBlock.length);
            message.set(message.size() - 1, paddedBlock); // nadpisz ostatni blok
        }

        // Dodajemy osobny blok z długością paddingu
        byte[] paddingInfoBlock = new byte[8];
        paddingInfoBlock[0] = (byte) paddingLength;
        message.add(paddingInfoBlock);



    }

    public static void unpadMessage(List<byte[]> message) { // Usunięcie paddingu z wiadomości
        int paddingLength = message.getLast()[0];
        message.removeLast();
        byte[] unpaddedMessage = new byte[message.getLast().length - paddingLength]; // Tablica na wiadomość bez paddingu
        System.arraycopy(message.getLast(), 0, unpaddedMessage, 0, unpaddedMessage.length); // Skopiowanie wiadomości do tablicy bez paddingu
        message.set(message.size() - 1, unpaddedMessage);

    }
}
