package com.jwtdecode.ui;

import com.jwtdecode.core.BruteForceEngine;
import com.jwtdecode.core.JwtForger;
import com.jwtdecode.core.JwtToken;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.ScrollPane;
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

    // === Main scroll pane ===
    @FXML private ScrollPane mainScrollPane;

    // === JWT input ===
    @FXML private TextArea jwtInputArea;

    // === Forge workspace ===
    @FXML private TextArea forgeHeaderArea;
    @FXML private TextArea forgePayloadArea;
    @FXML private TextArea forgeKeyArea;
    @FXML private Button   forgeBtn;
    @FXML private TextArea forgeResultArea;

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

        // Forge area placeholders
        forgeHeaderArea.setPromptText("粘贴JWT后自动填充，或手动输入Header JSON");
        forgePayloadArea.setPromptText("粘贴JWT后自动填充，或手动输入Payload JSON");
        forgeKeyArea.setPromptText("输入HS密钥（字符串）或RS/ES/PS私钥（PEM格式）");
        forgeResultArea.setEditable(false);
        forgeResultArea.setPromptText("点击「生成伪造JWT」后在此显示结果");

        // Auto-parse JWT into forge areas when JWT input changes
        jwtInputArea.textProperty().addListener((obs, oldVal, newVal) -> {
            String text = newVal == null ? "" : newVal.trim();
            if (text.isEmpty()) return;
            try {
                JwtToken token = new JwtToken(text);
                forgeHeaderArea.setText(prettyJson(token.getHeaderJson()));
                forgePayloadArea.setText(prettyJson(token.getPayloadJson()));
            } catch (Exception ignored) {
                // Not a valid JWT yet, don't update
            }
        });

        // Speed up scroll: intercept mouse wheel and multiply increment
        mainScrollPane.setOnScroll(e -> {
            double delta = e.getDeltaY() * 3 / mainScrollPane.getContent().getBoundsInLocal().getHeight();
            mainScrollPane.setVvalue(mainScrollPane.getVvalue() - delta);
            e.consume();
        });
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

    @FXML
    private void onForge() {
        String headerJson = forgeHeaderArea.getText().trim();
        String payloadJson = forgePayloadArea.getText().trim();
        String keyStr = forgeKeyArea.getText().trim();

        if (headerJson.isEmpty() || payloadJson.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "提示", "请先填写 Header JSON 和 Payload JSON！\n（粘贴JWT令牌后会自动填充）");
            return;
        }
        if (keyStr.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "提示", "请输入密钥或PEM私钥！");
            return;
        }

        // Extract algorithm from header JSON
        String alg = extractAlgFromJson(headerJson);
        if (alg == null) {
            showAlert(Alert.AlertType.ERROR, "错误", "无法从Header JSON中提取算法字段（alg），请确认Header格式正确。");
            return;
        }

        try {
            String forged = JwtForger.forge(alg, headerJson, payloadJson, keyStr);
            forgeResultArea.setText(forged);
        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "伪造失败", e.getMessage());
        }
    }

    /**
     * Extract "alg" value from a JSON string without external dependencies.
     */
    private String extractAlgFromJson(String json) {
        int idx = json.indexOf("\"alg\"");
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    /**
     * Very simple JSON pretty-printer: adds newlines after commas and braces.
     * Only used for display; not a full parser.
     */
    private String prettyJson(String json) {
        if (json == null) return "";
        StringBuilder sb = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"' && (i == 0 || json.charAt(i - 1) != '\\')) inString = !inString;
            if (!inString) {
                if (c == '{' || c == '[') {
                    sb.append(c).append('\n');
                    indent += 2;
                    appendIndent(sb, indent);
                    continue;
                } else if (c == '}' || c == ']') {
                    sb.append('\n');
                    indent -= 2;
                    appendIndent(sb, indent);
                    sb.append(c);
                    continue;
                } else if (c == ',') {
                    sb.append(c).append('\n');
                    appendIndent(sb, indent);
                    continue;
                } else if (c == ':') {
                    sb.append(c).append(' ');
                    continue;
                } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    continue; // strip original whitespace
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private void appendIndent(StringBuilder sb, int indent) {
        for (int i = 0; i < indent; i++) sb.append(' ');
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
