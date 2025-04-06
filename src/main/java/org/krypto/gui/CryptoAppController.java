package org.krypto.gui;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.krypto.logic.FileDao;

public class CryptoAppController {
    @FXML private TextField key1Field;
    @FXML private TextField key2Field;
    @FXML private TextField key3Field;

    @FXML private TextArea plainTextArea;
    @FXML private TextArea cipherTextArea;

    @FXML private ToggleGroup modeToggleGroup;



    @FXML private TextField plainFilePath;
    @FXML private TextField cipherFilePath;

    @FXML
    private void onOpenPlain() {
        openFile(plainFilePath.getText());
    }
    @FXML
    private void onSavePlain() {
        saveFile(plainTextArea.getText());
    }
    @FXML
    private void onOpenCipher() {
        openFile(cipherFilePath.getText());
    }

    @FXML
    private void onSaveCipher() {
        saveFile(cipherTextArea.getText());
    }


    private void openFile(String filePath) {
        var blocks = FileDao.read(filePath);
        if (blocks != null) {
            StringBuilder sb = new StringBuilder();
            for (byte[] block : blocks) {
                sb.append(new String(block));
            }
            plainTextArea.setText(sb.toString());
        }
    }

    @FXML private void saveFile(String content) {

        byte[] bytes = content.getBytes();

        for (int i = 0; i < bytes.length; i += 8) {
            byte[] block = new byte[8];
            int len = Math.min(8, bytes.length - i);
            System.arraycopy(bytes, i, block, 0, len);

        }


    }

    @FXML
    protected void onGenerateKeys() {
        key1Field.setText("abc123");
        key2Field.setText("def456");
        key3Field.setText("ghi789");
    }

    @FXML
    protected void onEncrypt() {
        cipherTextArea.setText("ZASZYFROWANY: " + plainTextArea.getText());
    }

    @FXML
    protected void onDecrypt() {
        plainTextArea.setText("ODSZYFROWANY: " + cipherTextArea.getText());
    }
}
