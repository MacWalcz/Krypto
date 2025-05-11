package org.krypto.gui;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.krypto.logic.ElGamal;

public class CryptoApp extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        ElGamal elGamal = new ElGamal();
        FXMLLoader loader = new FXMLLoader(CryptoApp.class.getResource("crypto-view.fxml"));

        Parent root = loader.load();
        ElGamalController controller = loader.getController();
        controller.setElGamal(elGamal);

        Scene scene = new Scene(root, 950, 600);
        primaryStage.setTitle("ElGamal Kryptografia");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}