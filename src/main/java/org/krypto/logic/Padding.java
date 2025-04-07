package org.krypto.logic;


import java.util.Arrays;
import java.util.List;

public class Padding {
    public static void padMessage(List<byte[]> blocks) { // Dodaje padding do ostatniego bloku wiadomości
        if (blocks == null || blocks.isEmpty()) { // Sprawdzamy, czy lista bloków nie jest pusta
            return; // Jeśli jest pusta, nie ma co dodawać paddingu
        }
       
        byte[] lastBlock = blocks.get(blocks.size() - 1); // Pobieramy ostatni blok wiadomości
        int lastBlockLen = lastBlock.length; // Sprawdzamy długość ostatniego bloku

        if (lastBlockLen < 8) {                 // Jeśli długość bloku jest mniejsza niż 8 bajtów
                                                // Dodajemy padding do ostatniego bloku, aby miał długość 8 bajtów

            int padCount = 8 - lastBlockLen;    // Obliczamy liczbę bajtów, które musimy dodać jako padding
            byte[] newBlock = Arrays.copyOf(lastBlock, 8); // Tworzymy nowy blok o długości 8 bajtów, kopiując zawartość ostatniego bloku
            for (int i = lastBlockLen; i < 8; i++) {
                newBlock[i] = (byte) padCount; // Wypełniamy nowy blok bajtami 
            }
            blocks.set(blocks.size() - 1, newBlock); // Ustawiamy nowy blok jako ostatni blok w liście bloków
        } else if (lastBlockLen == 8) { // Jeśli długość bloku jest równa 8 bajtom, dodajemy nowy blok jako padding
            byte[] extra = new byte[8]; // Tworzymy nowy blok o długości 8 bajtów
            Arrays.fill(extra, (byte) 8); // Wypełniamy nowy blok bajtami o wartości 8
            blocks.add(extra); // Dodajemy nowy blok jako padding do listy bloków
        } else {
      
            throw new IllegalArgumentException("Block has length > 8."); // Jeśli długość bloku jest większa niż 8 bajtów, zgłaszamy wyjątek
        }
    }

    public static void unpadMessage(List<byte[]> blocks) { // Usuwa padding z ostatniego bloku wiadomości
        if (blocks == null || blocks.isEmpty()) { // Sprawdzamy, czy lista bloków nie jest pusta
            return; // Jeśli jest pusta, nie ma co usuwać paddingu
        }
        byte[] lastBlock = blocks.get(blocks.size() - 1); // Pobieramy ostatni blok wiadomości
        if (lastBlock.length != 8) { // Sprawdzamy, czy długość ostatniego bloku wynosi 8 bajtów
            return; // Jeśli długość nie wynosi 8, nie ma paddingu do usunięcia
        }
        int padVal = lastBlock[7] & 0xFF; // Pobieramy wartość paddingu z ostatniego bajtu bloku
        if (padVal < 1 || padVal > 8) { // Sprawdzamy, czy wartość paddingu jest poprawna (1-8)
            return; // Jeśli wartość jest niepoprawna, nie usuwamy paddingu
        }
        for (int i = 8 - padVal; i < 8; i++) { // Sprawdzamy, czy ostatnie bajty bloku zawierają poprawny padding
            if ((lastBlock[i] & 0xFF) != padVal) { // Jeśli którykolwiek bajt nie pasuje do wartości paddingu
                return; // Nie usuwamy paddingu
            }
        }
       
        if (padVal == 8 && blocks.size() > 1) { // Jeśli cały blok to padding i istnieje więcej niż jeden blok
            blocks.remove(blocks.size() - 1); // Usuwamy cały blok z listy
        } else { // W przeciwnym razie
            byte[] trimmed = Arrays.copyOf(lastBlock, 8 - padVal); // Tworzymy nowy blok bez bajtów paddingu
            blocks.set(blocks.size() - 1, trimmed); // Zastępujemy ostatni blok obciętym blokiem
        }
    }
}

