module org.krypto.krypto {
    requires javafx.controls;
    requires javafx.fxml;


    opens org.krypto.krypto to javafx.fxml;
    exports org.krypto.krypto;
    exports org.krypto.gui;
    opens org.krypto.gui to javafx.fxml;
}