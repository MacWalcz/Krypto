package org.krypto.gui;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;



public class CryptoApp extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {

        FXMLLoader loader = new FXMLLoader(CryptoApp.class.getResource("crypto-view.fxml"));

        Parent root = loader.load();

        Scene scene = new Scene(root, 950, 600);
        primaryStage.setTitle("Kryptografia");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

