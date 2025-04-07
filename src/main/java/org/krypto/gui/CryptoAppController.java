package org.krypto.gui;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import org.krypto.logic.FileDao;

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
                openFile(fileName);
                if ("plain".equals(side))
                    plainFilePath.setText(fileName);
                if ("cipher".equals(side))
                    cipherFilePath.setText(fileName);

            }
        }
        if ("save".equals(io)) {
            File selectedFile = fileChooser.showSaveDialog(null);
            if (selectedFile != null) {
                String fileName = selectedFile.getAbsolutePath();
                saveFile(fileName, side);
                if ("plain".equals(side))
                    plainFilePath.setText(fileName);
                if ("cipher".equals(side))
                    cipherFilePath.setText(fileName);

        }
        }


    }



private void openFile(String filePath) {
    var blocks = FileDao.read(filePath);
    plainBytes = blocks;
    if (blocks != null) {
        StringBuilder sb = new StringBuilder();
        for (byte[] block : blocks) {
            sb.append(new String(block));
        }
        plainTextArea.setText(sb.toString());
    }
}

@FXML
private void saveFile(String filePath, String side) {

    if ("plain".equals(side))
        FileDao.write(plainBytes, filePath);
    if ("cipher".equals(side))
        FileDao.write(cipherBytes, filePath);

}

@FXML
protected void onGenerateKeys() {
    key1Field.setText("abc123");
    key2Field.setText("def456");
    key3Field.setText("ghi789");
}

@FXML
protected void onEncrypt() {
    cipherTextArea.setText("ZASZYFROWANY: " + plainBytes);
    cipherBytes = plainBytes;
}

@FXML
protected void onDecrypt() {
    plainTextArea.setText("ODSZYFROWANY: " + cipherTextArea.getText());
    plainBytes = cipherBytes;
}
}
