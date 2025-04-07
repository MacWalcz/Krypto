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

public class CryptoAppController {
    private List<byte[]> plainBytes = new ArrayList<>();
    private List<byte[]> cipherBytes = new ArrayList<>();

    private byte[] key1;
    private byte[] key2;
    private byte[] key3;

    @FXML
    private TextField key1Field;
    @FXML
    private TextField key2Field;
    @FXML
    private TextField key3Field;

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

    @FXML
    protected void onEncrypt() {
        try {
            des.setBaseKey(Converter.fromBase64ToByte(key1Field.getText()));
            if (fileCheckBox.isSelected()) {
                cipherBytes = des.encrypt(plainBytes);
                des.setBaseKey(Converter.fromBase64ToByte(key2Field.getText()));
                cipherBytes = des.decrypt(cipherBytes);
                des.setBaseKey(Converter.fromBase64ToByte(key3Field.getText()));
                cipherBytes = des.encrypt(cipherBytes);
                cipherTextArea.setText(cipherBytes.toString());
            }
            if (windowCheckBox.isSelected()) {

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @FXML
    protected void onDecrypt() {
        try {
            des.setBaseKey(Converter.fromBase64ToByte(key3Field.getText()));
            if (fileCheckBox.isSelected()) {
                plainBytes = des.decrypt(cipherBytes);
                des.setBaseKey(Converter.fromBase64ToByte(key2Field.getText()));
                plainBytes = des.encrypt(plainBytes);
                des.setBaseKey(Converter.fromBase64ToByte(key1Field.getText()));
                plainBytes = des.decrypt(plainBytes);
                plainTextArea.setText(plainBytes.toString());
            }
            if (windowCheckBox.isSelected()) {


            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }





//
//    protected List<byte[]> mockEncrypt() {
//        System.out.println(plainBytes);
//        List<byte[]> blocks = new ArrayList<>();
//
//        for (byte[] block : plainBytes) {
//            blocks.add(block.clone());
//        }
//        for (byte[] block : blocks) {
//            for (int i = 0; i < block.length; i++) {
//                block[i] = (byte) (block[i] + 0x1);
//            }
//        }
//
//        return blocks;
//    }
//
//    protected List<byte[]> mockDecrypt() {
//        System.out.println(cipherBytes);
//        List<byte[]> blocks = new ArrayList<>();
//
//        for (byte[] block : cipherBytes) {
//            blocks.add(block.clone());
//        }
//        for (byte[] block : blocks) {
//            for (int i = 0; i < block.length; i++) {
//                block[i] = (byte) (block[i] - 0x1);
//            }
//        }
//        return blocks;
//    }

}
