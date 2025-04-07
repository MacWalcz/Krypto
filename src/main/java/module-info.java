module org.krypto.gui {
    requires javafx.controls;
    requires javafx.fxml;
    // Otwiera pakiety dla frameworka JavaFX
    opens org.krypto.gui to javafx.fxml;

    // Eksportuj pakiety, aby były dostępne w innych modułach
    exports org.krypto.gui;
    exports org.krypto.logic;  // Jeśli chcesz eksportować także logiczny moduł
}