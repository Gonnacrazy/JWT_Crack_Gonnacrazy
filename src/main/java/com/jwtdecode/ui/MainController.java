package com.jwtdecode.ui;

import com.jwtdecode.core.BruteForceEngine;
import com.jwtdecode.core.JwtToken;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;

import java.io.File;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ResourceBundle;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainController implements Initializable {

    // === Dictionary selection ===
    @FXML private TextField dictPathField;
    @FXML private Button browseDictBtn;

    // === Options ===
    @FXML private CheckBox parallelCheckBox;

    // === JWT input ===
    @FXML private TextArea jwtInputArea;

    // === Control buttons ===
    @FXML private Button startBtn;
    @FXML private Button stopBtn;
    @FXML private Button clearBtn;

    // === Status ===
    @FXML private Label statusLabel;
    @FXML private ProgressBar progressBar;

    // === Result output ===
    @FXML private TextArea resultArea;

    // === Internal state ===
    private File selectedDict;
    private AtomicBoolean stopFlag = new AtomicBoolean(false);
    private ExecutorService executor;
    private boolean isRunning = false;

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // Default: parallel enabled
        parallelCheckBox.setSelected(true);

        // Initial button states
        stopBtn.setDisable(true);

        // Placeholder text
        jwtInputArea.setPromptText(
                "在此处粘贴要爆破的JWT令牌\n" +
                "例如：eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxxxx");

        resultArea.setEditable(false);
        resultArea.setWrapText(true);

        // Dict path field not editable, click to browse
        dictPathField.setEditable(false);
        dictPathField.setPromptText("点击右侧按钮选择字典文件 (*.txt)");
    }

    @FXML
    private void onBrowseDict() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("选择字典文件");
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("文本文件", "*.txt"),
                new FileChooser.ExtensionFilter("所有文件", "*.*")
        );
        if (selectedDict != null && selectedDict.getParentFile() != null) {
            chooser.setInitialDirectory(selectedDict.getParentFile());
        }
        File chosen = chooser.showOpenDialog(browseDictBtn.getScene().getWindow());
        if (chosen != null) {
            selectedDict = chosen;
            dictPathField.setText(chosen.getAbsolutePath());
            appendLog("[-] 已选择字典: " + chosen.getAbsolutePath());
        }
    }

    @FXML
    private void onStart() {
        if (isRunning) return;

        // Validate dictionary
        if (selectedDict == null || !selectedDict.exists()) {
            showAlert(Alert.AlertType.WARNING, "提示", "请先选择有效的字典文件！");
            return;
        }

        // Validate JWT
        String jwtText = jwtInputArea.getText().trim();
        if (jwtText.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "提示", "请输入要爆破的JWT令牌！");
            return;
        }

        JwtToken token;
        try {
            token = new JwtToken(jwtText);
        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "JWT格式错误", "无法解析JWT：\n" + e.getMessage());
            return;
        }

        // Display JWT info
        appendLog("━".repeat(60));
        appendLog("[*] 开始爆破 - " + now());
        appendLog("[*] 算法: " + token.getAlgorithm());
        appendLog("[*] Header: " + token.getHeaderJson());
        appendLog("[*] Payload: " + token.getPayloadJson());
        appendLog("[*] 字典: " + selectedDict.getName() +
                (parallelCheckBox.isSelected() ? "  [CPU并行模式]" : "  [单线程模式]"));
        appendLog("━".repeat(60));

        // Reset state
        stopFlag = new AtomicBoolean(false);
        isRunning = true;
        startBtn.setDisable(true);
        stopBtn.setDisable(false);
        statusLabel.setText("爆破中...");
        progressBar.setProgress(ProgressIndicator.INDETERMINATE_PROGRESS);

        // Build and start engine
        BruteForceEngine engine = new BruteForceEngine(
                token,
                selectedDict,
                parallelCheckBox.isSelected(),
                stopFlag,
                // Hit callback - called immediately when a key is found
                (key, count) -> Platform.runLater(() -> {
                    appendHit("[+] 命中密钥: " + key + "  (第 " + String.format("%,d", count) + " 条)");
                }),
                // Progress callback
                (count) -> Platform.runLater(() -> {
                    statusLabel.setText("已尝试: " + String.format("%,d", count) + " 条...");
                }),
                // Done callback
                (result) -> Platform.runLater(() -> {
                    isRunning = false;
                    startBtn.setDisable(false);
                    stopBtn.setDisable(true);
                    progressBar.setProgress(0);
                    statusLabel.setText(result.found ? "完成 - 已找到密钥！" : "完成 - 未找到");
                    appendLog("━".repeat(60));
                    appendLog("[*] " + result.message);
                    appendLog("━".repeat(60));
                })
        );

        // Run in background thread
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
        executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "brute-force-engine");
            t.setDaemon(true);
            return t;
        });
        executor.submit(engine::start);
    }

    @FXML
    private void onStop() {
        if (!isRunning) return;
        stopFlag.set(true);
        stopBtn.setDisable(true);
        statusLabel.setText("正在停止...");
        appendLog("[!] 用户请求停止爆破...");
    }

    @FXML
    private void onClear() {
        resultArea.clear();
        statusLabel.setText("就绪");
        progressBar.setProgress(0);
    }

    /**
     * Append a normal log line to the result area.
     */
    private void appendLog(String text) {
        resultArea.appendText(text + "\n");
    }

    /**
     * Append a highlighted hit line (key found).
     * Since TextArea doesn't support styling per-line, we use a prefix to make it visible
     * and append it with emphasis (surrounding blank lines for readability).
     */
    private void appendHit(String text) {
        resultArea.appendText("\n");
        resultArea.appendText("★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★\n");
        resultArea.appendText(text + "\n");
        resultArea.appendText("★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★ ★\n");
        resultArea.appendText("\n");
        // Scroll to bottom
        resultArea.positionCaret(resultArea.getText().length());
    }

    private String now() {
        return LocalDateTime.now().format(TIME_FMT);
    }

    private void showAlert(Alert.AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
