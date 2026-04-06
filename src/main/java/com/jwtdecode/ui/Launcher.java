package com.jwtdecode.ui;

/**
 * Launcher class - serves as the Main-Class in the fat JAR manifest.
 *
 * JavaFX requires the Application class to NOT be on the main thread's
 * initial class path in a fat JAR scenario. Using an intermediate Launcher
 * class that calls Application.launch() works around this restriction.
 *
 * This is the class referenced in the MANIFEST.MF Main-Class attribute.
 */
public class Launcher {

    public static void main(String[] args) {
        MainApp.main(args);
    }
}
