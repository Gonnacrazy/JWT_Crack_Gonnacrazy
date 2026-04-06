package com.jwtdecode.ui;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.InputStream;

public class MainApp extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/jwtdecode/ui/main.fxml"));
        Scene scene = new Scene(loader.load(), 900, 700);

        // Load CSS
        String cssUrl = getClass().getResource("/com/jwtdecode/ui/style.css") != null
                ? getClass().getResource("/com/jwtdecode/ui/style.css").toExternalForm()
                : null;
        if (cssUrl != null) {
            scene.getStylesheets().add(cssUrl);
        }

        primaryStage.setTitle("JWT_Crack_Gonnacrazy  —  JWT密钥爆破工具");
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(800);
        primaryStage.setMinHeight(600);

        // Try to load icon (supports png and jpg)
        try {
            InputStream iconStream = getClass().getResourceAsStream("/icons/icon.jpg");
            if (iconStream == null) {
                iconStream = getClass().getResourceAsStream("/icons/icon.png");
            }
            if (iconStream != null) {
                primaryStage.getIcons().add(new Image(iconStream));
            }
        } catch (Exception ignored) {}

        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
