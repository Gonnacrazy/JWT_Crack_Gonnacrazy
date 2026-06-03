package com.jwtdecode.core;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * Forge a new JWT by re-signing modified header/payload with a known key.
 * Supports HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512.
 */
public class JwtForger {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Forge a JWT.
     *
     * @param algorithm  e.g. "HS256", "RS256", "ES256", "PS384"
     * @param headerJson  modified header JSON string
     * @param payloadJson modified payload JSON string
     * @param keyStr      secret string (HS) or PEM private key (RS/PS/ES)
     * @return complete forged JWT string
     * @throws Exception on any signing failure
     */
    public static String forge(String algorithm, String headerJson, String payloadJson, String keyStr)
            throws Exception {
        // Re-encode header and payload as base64url (without padding)
        String headerB64  = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64 + "." + payloadB64;

        String alg = algorithm.toUpperCase();
        byte[] sigBytes;

        if (alg.startsWith("HS")) {
            sigBytes = signHmac(alg, signingInput, keyStr);
        } else if (alg.startsWith("RS") || alg.startsWith("PS")) {
            sigBytes = signRsa(alg, signingInput, keyStr);
        } else if (alg.startsWith("ES")) {
            sigBytes = signEc(alg, signingInput, keyStr);
        } else {
            throw new Exception("不支持的算法: " + algorithm);
        }

        return signingInput + "." + base64UrlEncode(sigBytes);
    }

    // ===== HMAC =====

    private static byte[] signHmac(String alg, String signingInput, String secret) throws Exception {
        String macAlg;
        switch (alg) {
            case "HS256": macAlg = "HmacSHA256"; break;
            case "HS384": macAlg = "HmacSHA384"; break;
            case "HS512": macAlg = "HmacSHA512"; break;
            default: throw new Exception("未知HS算法: " + alg);
        }
        Mac mac = Mac.getInstance(macAlg);
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlg));
        return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
    }

    // ===== RSA / RSA-PSS =====

    private static byte[] signRsa(String alg, String signingInput, String keyStr) throws Exception {
        PemKeyParser.ParsedKey parsed = PemKeyParser.parse(keyStr);
        if (parsed == null || parsed.privateKey == null) {
            throw new Exception("无法解析私钥PEM，请确认输入的是RSA私钥（BEGIN RSA PRIVATE KEY 或 BEGIN PRIVATE KEY）");
        }

        String javaAlg;
        if (alg.startsWith("PS")) {
            switch (alg) {
                case "PS256": javaAlg = "SHA256withRSAandMGF1"; break;
                case "PS384": javaAlg = "SHA384withRSAandMGF1"; break;
                case "PS512": javaAlg = "SHA512withRSAandMGF1"; break;
                default: throw new Exception("未知PS算法: " + alg);
            }
        } else {
            switch (alg) {
                case "RS256": javaAlg = "SHA256withRSA"; break;
                case "RS384": javaAlg = "SHA384withRSA"; break;
                case "RS512": javaAlg = "SHA512withRSA"; break;
                default: throw new Exception("未知RS算法: " + alg);
            }
        }

        Signature sig = Signature.getInstance(javaAlg, "BC");
        sig.initSign(parsed.privateKey);
        sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return sig.sign();
    }

    // ===== ECDSA =====

    private static byte[] signEc(String alg, String signingInput, String keyStr) throws Exception {
        PemKeyParser.ParsedKey parsed = PemKeyParser.parse(keyStr);
        if (parsed == null || parsed.privateKey == null) {
            throw new Exception("无法解析私钥PEM，请确认输入的是EC私钥（BEGIN EC PRIVATE KEY 或 BEGIN PRIVATE KEY）");
        }

        String javaAlg;
        int componentLen;
        switch (alg) {
            case "ES256": javaAlg = "SHA256withECDSA"; componentLen = 32; break;
            case "ES384": javaAlg = "SHA384withECDSA"; componentLen = 48; break;
            case "ES512": javaAlg = "SHA512withECDSA"; componentLen = 66; break;
            default: throw new Exception("未知ES算法: " + alg);
        }

        Signature sig = Signature.getInstance(javaAlg, "BC");
        sig.initSign(parsed.privateKey);
        sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
        byte[] derSig = sig.sign();

        // Convert DER signature to JWT raw R||S format
        return derToRaw(derSig, componentLen);
    }

    /**
     * Convert DER-encoded ECDSA signature to JWT raw R||S format.
     */
    private static byte[] derToRaw(byte[] der, int componentLen) throws Exception {
        // DER: 0x30 len 0x02 rLen r... 0x02 sLen s...
        if (der[0] != 0x30) throw new Exception("无效的DER签名格式");
        int offset = 2;
        if (der[1] == (byte) 0x81) offset = 3; // long form length

        if (der[offset] != 0x02) throw new Exception("无效的DER签名格式（R）");
        int rLen = der[offset + 1] & 0xFF;
        byte[] r = new byte[rLen];
        System.arraycopy(der, offset + 2, r, 0, rLen);

        offset += 2 + rLen;
        if (der[offset] != 0x02) throw new Exception("无效的DER签名格式（S）");
        int sLen = der[offset + 1] & 0xFF;
        byte[] s = new byte[sLen];
        System.arraycopy(der, offset + 2, s, 0, sLen);

        // Trim leading zeros and left-pad to componentLen
        byte[] result = new byte[componentLen * 2];
        copyPadded(r, result, 0, componentLen);
        copyPadded(s, result, componentLen, componentLen);
        return result;
    }

    private static void copyPadded(byte[] src, byte[] dst, int dstOffset, int len) {
        // Strip leading zero bytes (DER adds them for sign)
        int start = 0;
        while (start < src.length - 1 && src[start] == 0) start++;
        byte[] stripped = new byte[src.length - start];
        System.arraycopy(src, start, stripped, 0, stripped.length);

        // Right-align into destination
        int copyStart = len - stripped.length;
        if (copyStart < 0) {
            // Truncate (shouldn't happen with correct key)
            System.arraycopy(stripped, -copyStart, dst, dstOffset, len);
        } else {
            System.arraycopy(stripped, 0, dst, dstOffset + copyStart, stripped.length);
        }
    }

    // ===== Base64url =====

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
