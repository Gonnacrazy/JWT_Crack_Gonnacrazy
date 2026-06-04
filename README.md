# JWT_Crack_Gonnacrazy

> JWT 密钥爆破 & 伪造工具 

参考了[JWT_Decode-wuwu](https://github.com/3wdsys-cyber/JWT_Decode-wuwu) by [3wdsys-cyber](https://github.com/3wdsys-cyber)，但是完全没有使用原码，是重新编写的

---

## 功能特性

### 密钥爆破

| 算法 | 说明 |
|------|------|
| HS256 / HS384 / HS512 | HMAC 对称密钥，支持 UTF-8 字符串和 base64url 编码密钥 |
| RS256 / RS384 / RS512 | RSA PKCS#1 签名，支持 PEM 公钥 / 私钥 |
| PS256 / PS384 / PS512 | RSA-PSS 签名，支持 PEM 公钥 / 私钥 |
| ES256 / ES384 / ES512 | ECDSA 签名，支持 PEM 公钥 / 私钥 / base64url 原始密钥 |

> 不支持 EdDSA (Ed25519 / Ed448)

- **PEM 证书字典支持**：字典中可混合普通字符串和 PEM 格式的公钥、私钥（PKCS#1 / PKCS#8）、X.509 证书
- **ES base64url 密钥**：字典中 EC 密钥可为 base64url 编码的原始字节，自动尝试解码
- **CPU 并行爆破**：利用全部 CPU 核心多线程爆破，大幅提速
- **实时命中显示**：找到密钥立即弹出，无需等待全部跑完
- **手动停止**：爆破过程中可随时中断，无需强杀进程

### JWT 解析 & 伪造

- 粘贴 JWT 后自动解码 Header 和 Payload 为 JSON（格式化显示）
- Header 和 Payload **独立可编辑**，可自由修改
- 输入密钥或 PEM 私钥后，一键生成伪造后的完整 JWT
- 支持 HS / RS / PS / ES 全系列算法的重签名

---

## 快速使用

下载 `JWT_Crack_Gonnacrazy.exe`以及Java环境，双击运行。

<img width="2559" height="1528" alt="屏幕截图 2026-06-04 214131" src="https://github.com/user-attachments/assets/610a5188-e7d1-42ca-86ef-5472fc9fa354" />


### 爆破流程

1. **选择字典**：点击「选择字典」按钮，选取 `.txt` 文件（一行一条）
2. **输入 JWT**：将目标 JWT 粘贴到「JWT令牌」输入框
3. **勾选并行**：推荐开启 CPU 并行模式
4. **开始爆破**：点击「开始爆破」，命中密钥实时显示
5. **停止**：可随时点击「停止爆破」中断

### 伪造 JWT

1. 在 JWT 输入框粘贴原始 JWT，Header / Payload 自动填充到伪造工作区
2. 按需修改 Header 或 Payload 的 JSON 内容
3. 在密钥框中输入爆破得到的密钥（HS 为字符串，RS/ES/PS 为 PEM 私钥）
4. 点击「生成伪造 JWT」，结果框直接复制使用

---

## 项目结构

```
src/main/java/com/jwtdecode/
├── core/
│   ├── BruteForceEngine.java   # 爆破引擎（单线程/并行）
│   ├── JwtForger.java          # JWT 重签名伪造
│   ├── JwtToken.java           # JWT 解析（Header/Payload/Signature）
│   ├── JwtVerifier.java        # 签名验证（HS/RS/PS/ES）
│   └── PemKeyParser.java       # PEM 证书/密钥解析
└── ui/
    ├── Launcher.java            # 启动入口（Fat JAR Main-Class）
    ├── MainApp.java             # JavaFX 应用
    └── MainController.java      # 界面控制器

src/main/resources/
├── com/jwtdecode/ui/
│   ├── main.fxml                # 界面布局
│   └── style.css                # 暗色主题样式
└── icons/
    └── icon.jpg                 # 应用图标
```

---

## 技术栈

| 组件 | 版本 |
|------|------|
| Java | 11 |
| JavaFX | 11.0.2 |
| Bouncy Castle | 1.70 |
| Jackson | 2.13.5 |
| Maven Shade Plugin | 3.4.1 |

---

## v1.0.1 更新

- 新增 **JWT 解析 & 伪造工作区**：支持 Header/Payload 可视化编辑 + 全算法重签名

---



