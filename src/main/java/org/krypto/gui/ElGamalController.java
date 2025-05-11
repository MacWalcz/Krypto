package org.krypto.gui;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import org.krypto.logic.ElGamal;
import org.krypto.logic.FileDao;
import org.krypto.logic.Padding;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ElGamalController {
    private ElGamal elGamal;
    private List<byte[]> plainBytes = new ArrayList<>();
    private List<BigInteger[]> cipherBlocks = new ArrayList<>();

    @FXML private TextField pField;
    @FXML private TextField gField;
    @FXML private TextField eField;
    @FXML private TextField openKeyFilePath;
    @FXML private TextField saveKeyFilePath;

    @FXML private CheckBox fileCheckBox;
    @FXML private CheckBox windowCheckBox;

    @FXML private TextArea plainTextArea;
    @FXML private TextArea cipherTextArea;
    @FXML private TextField plainFilePath;
    @FXML private TextField cipherFilePath;

    public void setElGamal(ElGamal elGamal) {
        this.elGamal = elGamal;
    }

    @FXML
    protected void onGenerateKeys() {
        elGamal.generateKeys();
        BigInteger[] pub = elGamal.getPubKey();
        pField.setText(Base64.getEncoder().encodeToString(pub[0].toByteArray()));
        gField.setText(Base64.getEncoder().encodeToString(pub[1].toByteArray()));
        eField.setText(Base64.getEncoder().encodeToString(pub[2].toByteArray()));
    }

    @FXML private void onOpenKeys() { fileManager("open", "keys"); }
    @FXML private void onSaveKeys() { fileManager("save", "keys"); }
    @FXML private void onOpenPlain() { fileManager("open", "plain"); }
    @FXML private void onSavePlain() { fileManager("save", "plain"); }
    @FXML private void onOpenCipher() { fileManager("open", "cipher"); }
    @FXML private void onSaveCipher() { fileManager("save", "cipher"); }

    private void fileManager(String mode, String type) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Wybierz plik");
        File file = "open".equals(mode) ? chooser.showOpenDialog(null) : chooser.showSaveDialog(null);
        if (file == null) return;
        String path = file.getAbsolutePath();

        switch (type) {
            case "keys":
                if ("open".equals(mode)) {
                    List<byte[]> kb = FileDao.read(path, Integer.MAX_VALUE);
                    if (kb != null && kb.size() >= 3) {
                        openKeyFilePath.setText(path);
                        pField.setText(Base64.getEncoder().encodeToString(kb.get(0)));
                        gField.setText(Base64.getEncoder().encodeToString(kb.get(1)));
                        eField.setText(Base64.getEncoder().encodeToString(kb.get(2)));
                        elGamal.setPubKey(new BigInteger[]{
                                new BigInteger(1, kb.get(0)),
                                new BigInteger(1, kb.get(1)),
                                new BigInteger(1, kb.get(2))
                        });
                    }
                } else {
                    List<byte[]> stream = List.of(
                            Base64.getDecoder().decode(pField.getText()),
                            Base64.getDecoder().decode(gField.getText()),
                            Base64.getDecoder().decode(eField.getText())
                    );
                    FileDao.write(stream, path);
                    saveKeyFilePath.setText(path);
                }
                break;

            case "plain":
                if ("open".equals(mode)) {
                    int blockSize = elGamal.getPubKey()[0].bitLength()/8;
                    plainBytes = FileDao.read(path, blockSize);
                    if (plainBytes != null) {
                        plainTextArea.setText(new String(FileDao.concat(plainBytes), StandardCharsets.UTF_8));
                        plainFilePath.setText(path);
                    }
                } else {
                    FileDao.write(plainBytes, path);
                    plainFilePath.setText(path);
                }
                break;

            case "cipher":
                if ("open".equals(mode)) {
                    cipherBlocks = FileDao.readCipher(path);
                    cipherTextArea.setText(FileDao.cipherToString(cipherBlocks));
                    cipherFilePath.setText(path);
                } else {
                    FileDao.writeCipher(cipherBlocks, path);
                    cipherFilePath.setText(path);
                }
                break;
        }
    }

    @FXML
    protected void onEncrypt() {
        if (windowCheckBox.isSelected()) {
            byte[] data = plainTextArea.getText().getBytes(StandardCharsets.UTF_8);
            int bs = elGamal.getPubKey()[0].bitLength()/8;
            List<byte[]> blocks = FileDao.split(data, bs);
            Padding.padMessage(blocks, bs);
            cipherBlocks = elGamal.encrypt(blocks);
            cipherTextArea.setText(FileDao.cipherToString(cipherBlocks));
        }
    }

    @FXML
    protected void onDecrypt() {
        if (windowCheckBox.isSelected()) {
            List<BigInteger[]> pairs = FileDao.parseString(cipherTextArea.getText());
            List<byte[]> msg = elGamal.decrypt(pairs);
            int bs = elGamal.getPubKey()[0].bitLength()/8;
            Padding.unpadMessage(msg, bs);
            plainTextArea.setText(new String(FileDao.concat(msg), StandardCharsets.UTF_8));
        }
    }
}