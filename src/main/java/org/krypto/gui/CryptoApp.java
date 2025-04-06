package org.krypto.gui;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

public class CryptoApp extends Application {

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Kryptografia");

        // Główne zakładki
        TabPane tabPane = new TabPane();
        Tab symTab = new Tab("Algorytmy symetryczne", createTripleDESPane());
        symTab.setClosable(false);
        tabPane.getTabs().add(symTab);

        Scene scene = new Scene(tabPane, 950, 600);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private VBox createTripleDESPane() {
        VBox mainLayout = new VBox(15);
        mainLayout.setPadding(new Insets(15));

        // Sekcja kluczy
        GridPane keyPane = new GridPane();
        keyPane.setHgap(10);
        keyPane.setVgap(10);

        TextField key1 = new TextField();
        TextField key2 = new TextField();
        TextField key3 = new TextField();

        Button generateKeys = new Button("Generuj klucze");
        TextField keyFileField = new TextField();
        Button loadKeys = new Button("Wczytaj");
        TextField saveKeyField = new TextField();
        Button saveKeys = new Button("Zapisz");

        keyPane.add(new Label("Wartość I klucza"), 0, 0);
        keyPane.add(key1, 1, 0);
        keyPane.add(new Label("Wartość II klucza"), 0, 1);
        keyPane.add(key2, 1, 1);
        keyPane.add(new Label("Wartość III klucza"), 0, 2);
        keyPane.add(key3, 1, 2);

        keyPane.add(generateKeys, 2, 1);

        keyPane.add(new Label("Wczytaj klucze z pliku"), 0, 3);
        keyPane.add(keyFileField, 1, 3);
        keyPane.add(loadKeys, 2, 3);

        keyPane.add(new Label("Zapisz klucze do pliku"), 0, 4);
        keyPane.add(saveKeyField, 1, 4);
        keyPane.add(saveKeys, 2, 4);

        // Sekcja szyfrowania
        HBox encryptionBox = new HBox(20);
        encryptionBox.setAlignment(Pos.TOP_CENTER);

        // Tekst jawny
        VBox plainTextBox = new VBox(10);
        TextField plainFile = new TextField();
        plainFile.setId("openPlainPath");
        Button openPlain = new Button("Otwórz");
        openPlain.setId("openPlainButton");
        TextArea plainText = new TextArea();
        plainText.setPrefHeight(200);
        TextField savePlainFile = new TextField();
        savePlainFile.setId("savePlainPath");
        Button savePlain = new Button("Zapisz");
        savePlain.setId("savePlainButton");

        plainTextBox.getChildren().addAll(
                new Label("Otwórz plik zawierający tekst jawny"),
                new HBox(10, plainFile, openPlain),
                plainText,
                new HBox(10, new Label("Zapisz plik zawierający tekst jawny"), savePlainFile, savePlain)
        );

        // Tekst zaszyfrowany
        VBox cipherTextBox = new VBox(10);
        TextField cipherFile = new TextField();
        cipherFile.setId("openCipherPath");
        Button openCipher = new Button("Otwórz");
        openCipher.setId("openCipherButton");
        TextArea cipherText = new TextArea();
        cipherText.setPrefHeight(200);
        TextField saveCipherFile = new TextField();
        saveCipherFile.setId("saveCipherPath");
        Button saveCipher = new Button("Zapisz");
        saveCipher.setId("saveCipherButton");

        cipherTextBox.getChildren().addAll(
                new Label("Otwórz plik zawierający szyfrogram"),
                new HBox(10, cipherFile, openCipher),
                cipherText,
                new HBox(10, new Label("Zapisz plik zawierający szyfrogram"), saveCipherFile, saveCipher)
        );

        // Środkowe przyciski
        VBox centerButtons = new VBox(15);
        centerButtons.setAlignment(Pos.CENTER);
        Button encryptBtn = new Button("Szyfruj →");
        Button decryptBtn = new Button("← Deszyfruj");

        ToggleGroup tg = new ToggleGroup();
        RadioButton rbFile = new RadioButton("Plik");
        rbFile.setToggleGroup(tg);
        rbFile.setSelected(true);
        RadioButton rbWindow = new RadioButton("Okno");
        rbWindow.setToggleGroup(tg);

        centerButtons.getChildren().addAll(encryptBtn, decryptBtn, rbFile, rbWindow);

        encryptionBox.getChildren().addAll(plainTextBox, centerButtons, cipherTextBox);

        mainLayout.getChildren().addAll(new Label("Algorytm TripleDES"), keyPane, new Separator(), encryptionBox);
        return mainLayout;
    }

    public static void main(String[] args) {
        launch(args);
    }
}

