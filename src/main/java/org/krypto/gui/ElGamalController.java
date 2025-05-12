package org.krypto.gui;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import org.krypto.logic.ElGamal;
import org.krypto.logic.FileDao;
import org.krypto.logic.Padding;
import org.krypto.logic.Converter;

import java.io.*;
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
    @FXML private TextField aField;
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
        BigInteger[] pub = elGamal.getPubKey();
        pField.setText(Converter.fromBigIntegerToHex(pub[0]));
        gField.setText(Converter.fromBigIntegerToHex(pub[1]));
        eField.setText(Converter.fromBigIntegerToHex(pub[2]));
        aField.setText(Converter.fromBigIntegerToHex(elGamal.getPrivKey()));
    }

    @FXML
    protected void onGenerateKeys() {
        elGamal.generateKeys();
        BigInteger[] pub = elGamal.getPubKey();
        pField.setText(Converter.fromBigIntegerToHex(pub[0]));
        gField.setText(Converter.fromBigIntegerToHex(pub[1]));
        eField.setText(Converter.fromBigIntegerToHex(pub[2]));
        aField.setText(Converter.fromBigIntegerToHex(elGamal.getPrivKey()));
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
                    BigInteger[] kb = new BigInteger[4];
                    try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(path))) {
                        for (int i = 0; i < kb.length; i++) {
                            kb[i] = (BigInteger) in.readObject();
                        }

                    } catch (IOException | ClassNotFoundException e) {
                        e.printStackTrace();
                    }

                    if (kb != null && kb.length >= 3) {
                        openKeyFilePath.setText(path);

                        pField.setText(Converter.fromBigIntegerToHex(kb[0]));
                        gField.setText(Converter.fromBigIntegerToHex(kb[1]));
                        eField.setText(Converter.fromBigIntegerToHex(kb[2]));
                        aField.setText(Converter.fromBigIntegerToHex(kb[3]));
                        elGamal.setPubKey(new BigInteger[]{
                                kb[0],
                                kb[1],
                                kb[2]
                        });
                        elGamal.setPrivKey(kb[3]);
                    }
                } else {
                    List<BigInteger> stream = List.of(
                            Converter.fromHexToBigInteger(pField.getText()),
                            Converter.fromHexToBigInteger(gField.getText()),
                            Converter.fromHexToBigInteger(eField.getText()),
                            Converter.fromHexToBigInteger(aField.getText())
                    );

                    try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(path))) {
                        for (BigInteger number : stream) {
                            out.writeObject(number);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    saveKeyFilePath.setText(path);
                }
                break;

            case "plain":
                if ("open".equals(mode)) {
                    int blockSize = 63;
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
            List<byte[]> blocks = FileDao.split(data, 63);
            Padding.padMessage(blocks, 63);
            cipherTextArea.setText(FileDao.cipherToString( elGamal.encrypt(blocks)));
        }
        if (fileCheckBox.isSelected()) {
            Padding.padMessage(plainBytes,63);
            cipherBlocks = elGamal.encrypt(plainBytes);
            cipherTextArea.setText(FileDao.cipherToString(cipherBlocks));

        }
    }

    @FXML
    protected void onDecrypt() {
        if (windowCheckBox.isSelected()) {
            List<BigInteger[]> pairs = FileDao.parseString(cipherTextArea.getText());
            List<byte[]> msg = elGamal.decrypt(pairs);
            Padding.unpadMessage(msg, 63);
            plainTextArea.setText(new String(FileDao.concat(msg), StandardCharsets.UTF_8));
        }
        if (fileCheckBox.isSelected()) {
            plainBytes = elGamal.decrypt(cipherBlocks);
            Padding.unpadMessage(plainBytes, 63);
            plainTextArea.setText(new String(FileDao.concat(plainBytes), StandardCharsets.UTF_8));

        }
    }
}