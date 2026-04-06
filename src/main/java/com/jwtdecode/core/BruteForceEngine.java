package com.jwtdecode.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * JWT brute-force engine.
 *
 * Supports:
 *  - HS256/384/512  (HMAC secret key as UTF-8 string or base64url bytes)
 *  - RS256/384/512  (RSA public/private key from PEM)
 *  - PS256/384/512  (RSA-PSS public/private key from PEM)
 *  - ES256/384/512  (EC public/private key from PEM, with base64url raw key support)
 *
 * Features:
 *  - Multi-threaded parallel brute force
 *  - Real-time hit callback (called immediately when a key is found)
 *  - Cancellation via AtomicBoolean stop flag
 *  - Progress callback with count
 */
public class BruteForceEngine {

    /**
     * Result of a brute-force attempt.
     */
    public static class BruteForceResult {
        public final boolean found;
        public final String key;
        public final long triedCount;
        public final String message;

        public BruteForceResult(boolean found, String key, long triedCount, String message) {
            this.found = found;
            this.key = key;
            this.triedCount = triedCount;
            this.message = message;
        }
    }

    private final JwtToken token;
    private final File dictionaryFile;
    private final boolean useParallel;
    private final AtomicBoolean stopFlag;

    /** Called immediately when a key match is found. Args: (key, triedCount) */
    private final BiConsumer<String, Long> hitCallback;

    /** Called periodically with progress. Args: (triedCount) */
    private final Consumer<Long> progressCallback;

    /** Called when the entire brute force is done. */
    private final Consumer<BruteForceResult> doneCallback;

    /** Algorithm family */
    private final AlgorithmFamily algFamily;

    private volatile long triedCount = 0;

    public enum AlgorithmFamily {
        HMAC,    // HS*
        RSA,     // RS*, PS*
        EC       // ES*
    }

    public BruteForceEngine(
            JwtToken token,
            File dictionaryFile,
            boolean useParallel,
            AtomicBoolean stopFlag,
            BiConsumer<String, Long> hitCallback,
            Consumer<Long> progressCallback,
            Consumer<BruteForceResult> doneCallback) {
        this.token = token;
        this.dictionaryFile = dictionaryFile;
        this.useParallel = useParallel;
        this.stopFlag = stopFlag;
        this.hitCallback = hitCallback;
        this.progressCallback = progressCallback;
        this.doneCallback = doneCallback;
        this.algFamily = detectFamily(token.getAlgorithm());
    }

    private AlgorithmFamily detectFamily(String alg) {
        if (alg == null) return AlgorithmFamily.HMAC;
        String upper = alg.toUpperCase();
        if (upper.startsWith("HS")) return AlgorithmFamily.HMAC;
        if (upper.startsWith("RS") || upper.startsWith("PS")) return AlgorithmFamily.RSA;
        if (upper.startsWith("ES")) return AlgorithmFamily.EC;
        return AlgorithmFamily.HMAC;
    }

    /**
     * Start brute force. This method blocks until done or stopped.
     * Should be called from a background thread.
     */
    public void start() {
        AtomicLong counter = new AtomicLong(0);
        AtomicBoolean foundAny = new AtomicBoolean(false);
        long startTime = System.currentTimeMillis();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(dictionaryFile), StandardCharsets.UTF_8), 65536)) {

            if (useParallel) {
                startParallel(reader, counter, foundAny);
            } else {
                startSingle(reader, counter, foundAny);
            }

        } catch (IOException e) {
            doneCallback.accept(new BruteForceResult(false, null, counter.get(),
                    "读取字典文件失败: " + e.getMessage()));
            return;
        }

        long elapsed = System.currentTimeMillis() - startTime;
        long total = counter.get();

        if (stopFlag.get()) {
            doneCallback.accept(new BruteForceResult(foundAny.get(), null, total,
                    String.format("已手动停止。共尝试 %,d 条，耗时 %s",
                            total, formatTime(elapsed))));
        } else {
            doneCallback.accept(new BruteForceResult(foundAny.get(), null, total,
                    String.format("爆破完成。共尝试 %,d 条，耗时 %s。%s",
                            total, formatTime(elapsed),
                            foundAny.get() ? "已找到密钥（见上方结果）" : "未找到匹配密钥")));
        }
    }

    private void startSingle(BufferedReader reader, AtomicLong counter, AtomicBoolean foundAny) throws IOException {
        String line;
        long lastReport = 0;
        while ((line = reader.readLine()) != null) {
            if (stopFlag.get()) break;
            if (line.isEmpty()) continue;

            counter.incrementAndGet();
            if (tryKey(line)) {
                foundAny.set(true);
                hitCallback.accept(line, counter.get());
                // Continue scanning (don't break - find all matches)
            }

            long cnt = counter.get();
            if (cnt - lastReport >= 50000) {
                progressCallback.accept(cnt);
                lastReport = cnt;
            }
        }
        progressCallback.accept(counter.get());
    }

    private void startParallel(BufferedReader reader, AtomicLong counter, AtomicBoolean foundAny) throws IOException {
        int threads = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        // Use a blocking queue as work distributor
        BlockingQueue<String> queue = new ArrayBlockingQueue<>(threads * 4);
        AtomicBoolean readerDone = new AtomicBoolean(false);

        // Submit worker tasks
        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                while (true) {
                    if (stopFlag.get()) break;
                    String key;
                    try {
                        // Poll with timeout to allow checking stop flag
                        key = queue.poll(50, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    if (key == null) {
                        if (readerDone.get() && queue.isEmpty()) break;
                        continue;
                    }
                    long cnt = counter.incrementAndGet();
                    if (tryKey(key)) {
                        foundAny.set(true);
                        hitCallback.accept(key, cnt);
                    }
                    if (cnt % 50000 == 0) {
                        progressCallback.accept(cnt);
                    }
                }
            });
        }

        // Read lines and feed queue
        String line;
        while ((line = reader.readLine()) != null) {
            if (stopFlag.get()) break;
            if (line.isEmpty()) continue;
            try {
                queue.put(line);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        readerDone.set(true);

        // Wait for all workers to finish
        executor.shutdown();
        try {
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        progressCallback.accept(counter.get());
    }

    /**
     * Try a single dictionary key against the JWT.
     * Handles all algorithm families appropriately.
     */
    private boolean tryKey(String keyStr) {
        switch (algFamily) {
            case HMAC:
                return tryHmacKey(keyStr);
            case RSA:
                return tryRsaKey(keyStr);
            case EC:
                return tryEcKey(keyStr);
            default:
                return false;
        }
    }

    /**
     * Try HMAC key. For HS* algorithms, try:
     * 1. Key as UTF-8 bytes
     * 2. Key as base64url decoded bytes (if key looks like base64url)
     */
    private boolean tryHmacKey(String keyStr) {
        // Try as UTF-8 string
        byte[] utf8Bytes = keyStr.getBytes(StandardCharsets.UTF_8);
        if (JwtVerifier.verifyHmac(token, utf8Bytes)) {
            return true;
        }

        // Try as base64url decoded bytes (for ES short key support mentioned in README)
        if (looksLikeBase64Url(keyStr)) {
            try {
                String padded = base64UrlToPadded(keyStr);
                byte[] decoded = Base64.getDecoder().decode(padded);
                if (decoded.length >= 32 && JwtVerifier.verifyHmac(token, decoded)) {
                    return true;
                }
            } catch (Exception ignored) {}
        }

        return false;
    }

    /**
     * Try RSA/PSS key from PEM string.
     */
    private boolean tryRsaKey(String keyStr) {
        PemKeyParser.ParsedKey parsed = PemKeyParser.parse(keyStr);
        if (parsed == null) return false;

        if (parsed.publicKey != null) {
            try {
                if (JwtVerifier.verifyRsa(token, parsed.publicKey)) return true;
            } catch (Exception ignored) {}
        }
        if (parsed.privateKey != null) {
            try {
                // Reconstruct public key from RSA private key using CRT parameters
                if (parsed.privateKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
                    java.security.interfaces.RSAPrivateCrtKey crtKey =
                            (java.security.interfaces.RSAPrivateCrtKey) parsed.privateKey;
                    java.security.spec.RSAPublicKeySpec pubSpec =
                            new java.security.spec.RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
                    java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA", "BC");
                    PublicKey pub = kf.generatePublic(pubSpec);
                    if (JwtVerifier.verifyRsa(token, pub)) return true;
                } else {
                    // PKCS#1 RSA private key without CRT: fall back to sign-and-compare (deterministic for RSA)
                    if (JwtVerifier.verifyRsaWithPrivate(token, parsed.privateKey)) return true;
                }
            } catch (Exception ignored) {}
        }
        return false;
    }

    /**
     * Try EC key from PEM string. Also tries base64url raw key material.
     */
    private boolean tryEcKey(String keyStr) {
        // Try as PEM
        if (keyStr.contains("-----BEGIN ")) {
            PemKeyParser.ParsedKey parsed = PemKeyParser.parse(keyStr);
            if (parsed != null) {
                if (parsed.publicKey != null) {
                    try {
                        if (JwtVerifier.verifyEc(token, parsed.publicKey)) return true;
                    } catch (Exception ignored) {}
                }
                if (parsed.privateKey != null) {
                    try {
                        if (JwtVerifier.verifyEcWithPrivate(token, parsed.privateKey)) return true;
                    } catch (Exception ignored) {}
                }
            }
            return false;
        }

        // Try as base64url encoded raw EC key (special ES base64url support)
        if (looksLikeBase64Url(keyStr)) {
            try {
                String padded = base64UrlToPadded(keyStr);
                byte[] raw = Base64.getDecoder().decode(padded);
                // Try to reconstruct EC public key from raw bytes for various curves
                PublicKey pub = tryBuildEcPublicKey(raw);
                if (pub != null && JwtVerifier.verifyEc(token, pub)) return true;
            } catch (Exception ignored) {}
        }

        // Also try as UTF-8 bytes interpreted as EC key material (unlikely but handle)
        return false;
    }

    /**
     * Attempt to build EC public key from raw uncompressed point bytes.
     */
    private PublicKey tryBuildEcPublicKey(byte[] raw) {
        // Try different EC curves based on algorithm
        String alg = token.getAlgorithm().toUpperCase();
        String[] curvesToTry;
        switch (alg) {
            case "ES256": curvesToTry = new String[]{"P-256"}; break;
            case "ES384": curvesToTry = new String[]{"P-384"}; break;
            case "ES512": curvesToTry = new String[]{"P-521"}; break;
            default: curvesToTry = new String[]{"P-256", "P-384", "P-521"};
        }

        // First, try as DER-encoded SubjectPublicKeyInfo (works for any curve)
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
            return kf.generatePublic(new java.security.spec.X509EncodedKeySpec(raw));
        } catch (Exception ignored) {}

        // Try as uncompressed point bytes for specific curves
        if (raw.length > 0 && raw[0] == 0x04) {
            for (String curve : curvesToTry) {
                try {
                    org.bouncycastle.jce.spec.ECNamedCurveParameterSpec curveSpec =
                            org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(curve);
                    org.bouncycastle.math.ec.ECPoint point = curveSpec.getCurve().decodePoint(raw);
                    org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec =
                            new org.bouncycastle.jce.spec.ECPublicKeySpec(point, curveSpec);
                    java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
                    return kf.generatePublic(pubSpec);
                } catch (Exception ignored) {}
            }
        }
        return null;
    }

    private boolean looksLikeBase64Url(String s) {
        if (s == null || s.length() < 4) return false;
        return s.matches("[A-Za-z0-9+/=_-]+");
    }

    private String base64UrlToPadded(String base64url) {
        String padded = base64url.replace('-', '+').replace('_', '/');
        int mod = padded.length() % 4;
        if (mod == 2) padded += "==";
        else if (mod == 3) padded += "=";
        return padded;
    }

    private String formatTime(long millis) {
        if (millis < 1000) return millis + "ms";
        long seconds = millis / 1000;
        if (seconds < 60) return seconds + "秒";
        long minutes = seconds / 60;
        long secs = seconds % 60;
        return minutes + "分" + secs + "秒";
    }
}
