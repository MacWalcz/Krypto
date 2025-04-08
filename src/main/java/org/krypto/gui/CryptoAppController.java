package org.krypto.gui;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import org.krypto.logic.Converter;
import org.krypto.logic.DES;
import org.krypto.logic.FileDao;
import org.krypto.logic.Generator;

import javax.swing.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class CryptoAppController {
    private List<byte[]> plainBytes = new ArrayList<>(); // pole dla bajtów wczytanych z pliku
    private List<byte[]> cipherBytes = new ArrayList<>(); //pole dla plików zakodowanych
    private List<byte[]> utfBytes = new ArrayList<>(); // pole dla okna jako utf8

    @FXML
    private TextField key1Field;
    @FXML
    private TextField key2Field;
    @FXML
    private TextField key3Field;

    @FXML
    private TextField openKeyFilePath;
    @FXML
    private TextField saveKeyFilePath;

    @FXML
    private CheckBox fileCheckBox;

    @FXML
    private CheckBox windowCheckBox;


    @FXML
    private TextArea plainTextArea;
    @FXML
    private TextArea cipherTextArea;
    @FXML
    private TextField plainFilePath;
    @FXML
    private TextField cipherFilePath;

    private DES des;  // Instancja DES

    public void showAlert() {
        Alert alert = new Alert(AlertType.INFORMATION);

        alert.setTitle("Informacja");

        alert.setHeaderText("Błędne klucze!");


        alert.showAndWait();
    }

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

    @FXML
    private void onOpenKeys() {
        fileChooserMenager("open", "keys");
    }

    @FXML
    private void onSaveKeys() {
        fileChooserMenager("save", "keys");
    }

    private void fileChooserMenager(String io, String side) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz plik");

        if ("open".equals(io)) {
            File selectedFile = fileChooser.showOpenDialog(null);
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
        List<byte[]> blocks = FileDao.read(filePath);

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
            if ("keys".equals(side)) {
                openKeyFilePath.setText(filePath);
                key1Field.setText(Converter.fromByteToBase64(blocks.get(0)));
                key2Field.setText(Converter.fromByteToBase64(blocks.get(1)));
                key3Field.setText(Converter.fromByteToBase64(blocks.get(2)));
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
        if ("keys".equals(side)) {
            List<byte[]> stream = new ArrayList<>();
            stream.add(Converter.fromBase64ToByte(key1Field.getText()));
            stream.add(Converter.fromBase64ToByte(key2Field.getText()));
            stream.add(Converter.fromBase64ToByte(key3Field.getText()));
            saveKeyFilePath.setText(filePath);
            FileDao.write(stream, filePath);
        }

    }

    @FXML
    protected void onGenerateKeys() {
        byte[][] keys = Generator.generate8ByteKeys(3);
        key1Field.setText(Converter.fromByteToBase64(keys[0]));
        key2Field.setText(Converter.fromByteToBase64(keys[1]));
        key3Field.setText(Converter.fromByteToBase64(keys[2]));
    }

    private boolean checkKeys() {
        if (key1Field.getText().length() != 12 || key2Field.getText().length() != 12 || key3Field.getText().length() != 12) {
            this.showAlert();
            return false;
        } else {

            return true;
        }
    }

    @FXML
    protected void onEncrypt() {
        if (checkKeys()) {
            try {
                des.setBaseKey(Converter.fromBase64ToByte(key1Field.getText()));
                if (fileCheckBox.isSelected()) {
                    cipherBytes = des.encrypt(plainBytes);
                    des.setBaseKey(Converter.fromBase64ToByte(key2Field.getText()));
                    cipherBytes = des.decrypt(cipherBytes);
                    des.setBaseKey(Converter.fromBase64ToByte(key3Field.getText()));
                    cipherBytes = des.encrypt(cipherBytes);
                    cipherTextArea.setText(Converter.fromListBytesToBase64(cipherBytes));
                }
                if (windowCheckBox.isSelected()) {
                    cipherTextArea.setText(Converter.fromListBytesToBase64(des.encrypt(Converter.fromUTF8ToList(plainTextArea.getText(),8))));
                    des.setBaseKey(Converter.fromBase64ToByte(key2Field.getText()));
                    cipherTextArea.setText(Converter.fromListBytesToBase64(des.decrypt(Converter.fromBase64ToList(cipherTextArea.getText(), 8))));
                    des.setBaseKey(Converter.fromBase64ToByte(key3Field.getText()));
                    cipherTextArea.setText(Converter.fromListBytesToBase64(des.encrypt(Converter.fromBase64ToList(cipherTextArea.getText(), 8))));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


    }

    @FXML
    protected void onDecrypt() {
        if (checkKeys()) {
            try {
                des.setBaseKey(Converter.fromBase64ToByte(key3Field.getText()));
                if (fileCheckBox.isSelected()) {
                    plainBytes = des.decrypt(cipherBytes);
                    des.setBaseKey(Converter.fromBase64ToByte(key2Field.getText()));
                    plainBytes = des.encrypt(plainBytes);
                    des.setBaseKey(Converter.fromBase64ToByte(key1Field.getText()));
                    plainBytes = des.decrypt(plainBytes);
                    plainTextArea.setText(Converter.fromListToUTF8(plainBytes));
                }
                if (windowCheckBox.isSelected()) {
                    utfBytes = des.decrypt(Converter.fromBase64ToList(cipherTextArea.getText(), 8));
                    des.setBaseKey(Converter.fromBase64ToByte(key2Field.getText()));
                    utfBytes = des.encrypt(utfBytes);
                    des.setBaseKey(Converter.fromBase64ToByte(key1Field.getText()));
                    utfBytes = des.decrypt(utfBytes);
                    plainTextArea.setText(Converter.fromListToUTF8(utfBytes));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        }

    }


}
