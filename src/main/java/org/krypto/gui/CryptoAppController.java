package org.krypto.gui;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import org.krypto.logic.DES;
import org.krypto.logic.FileDao;

import javax.swing.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class CryptoAppController {
    private List<byte[]> plainBytes = new ArrayList<>();
    private List<byte[]> cipherBytes = new ArrayList<>();


    @FXML
    private TextField key1Field;
    @FXML
    private TextField key2Field;
    @FXML
    private TextField key3Field;

    @FXML
    private TextArea plainTextArea;
    @FXML
    private TextArea cipherTextArea;

    @FXML
    private ToggleGroup modeToggleGroup;
    @FXML
    private RadioButton fileRadio;
    @FXML
    private RadioButton windowRadio;


    @FXML
    private TextField plainFilePath;
    @FXML
    private TextField cipherFilePath;

    private DES des;  // Instancja DES

    // Setter do ustawienia instancji DES
    public void setDes(DES des) {
        this.des = des;
    }

    @FXML
    private void onOpenPlain() {
        fileChooserMenager("open", "plain");
    }


    @FXML
    private void onSavePlain() {
        fileChooserMenager("save", "plain");
    }

    @FXML
    private void onOpenCipher() {
        fileChooserMenager("open", "cipher");
    }

    @FXML
    private void onSaveCipher() {
        fileChooserMenager("save", "cipher");
    }

    private void fileChooserMenager(String io, String side) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz plik");

        if ("open".equals(io)) {
            File selectedFile = fileChooser.showOpenDialog(null); // lub stage jeśli masz referencję
            if (selectedFile != null) {
                String fileName = selectedFile.getAbsolutePath();
                openFile(fileName, side);


            }
        }
        if ("save".equals(io)) {
            File selectedFile = fileChooser.showSaveDialog(null);
            if (selectedFile != null) {
                String fileName = selectedFile.getAbsolutePath();
                saveFile(fileName, side);


            }
        }


    }


    private void openFile(String filePath, String side) {
        var blocks = FileDao.read(filePath);

        if (blocks != null) {
            StringBuilder sb = new StringBuilder();
            for (byte[] block : blocks) {
                sb.append(new String(block));
            }
            if ("plain".equals(side)) {
                plainBytes = blocks;
                plainTextArea.setText(sb.toString());
                plainFilePath.setText(filePath);
            }
            if ("cipher".equals(side)) {
                cipherBytes = blocks;
                cipherTextArea.setText(sb.toString());
                cipherFilePath.setText(filePath);
            }
        }
    }

    @FXML
    private void saveFile(String filePath, String side) {

        if ("plain".equals(side)) {
            FileDao.write(plainBytes, filePath);
            plainFilePath.setText(filePath);
        }
        if ("cipher".equals(side)) {
            FileDao.write(cipherBytes, filePath);
            cipherFilePath.setText(filePath);
        }

    }

    @FXML
    protected void onGenerateKeys() {
        byte[][] keys = des.generateKeys();
        key1Field.setText(keys[0].toString());
        key2Field.setText(keys[1].toString());
        key3Field.setText(keys[2].toString());
    }

    @FXML
    protected void onEncrypt() {
        cipherBytes = mockEncrypt();
        cipherTextArea.setText(cipherBytes.toString());

    }

    @FXML
    protected void onDecrypt() {
        plainBytes = mockDecrypt();
        plainTextArea.setText(plainBytes.toString());

    }


    protected List<byte[]> mockEncrypt() {
        System.out.println(plainBytes);
        List<byte[]> blocks = new ArrayList<>();

        for (byte[] block : plainBytes) {
            blocks.add(block.clone());
        }
        for (byte[] block : blocks) {
            for (int i = 0; i < block.length; i++) {
                block[i] = (byte) (block[i] + 0x1);
            }
        }

        return blocks;
    }

    protected List<byte[]> mockDecrypt() {
        System.out.println(cipherBytes);
        List<byte[]> blocks = new ArrayList<>();

        for (byte[] block : cipherBytes) {
            blocks.add(block.clone());
        }
        for (byte[] block : blocks) {
            for (int i = 0; i < block.length; i++) {
                block[i] = (byte) (block[i] - 0x1);
            }
        }
        return blocks;
    }

}
