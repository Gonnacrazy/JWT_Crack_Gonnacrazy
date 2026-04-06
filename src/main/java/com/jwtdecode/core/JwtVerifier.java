package com.jwtdecode.core;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * JWT signature verifier - supports HS, RS, ES, PS algorithm families.
 * Uses BouncyCastle as the security provider for full algorithm coverage.
 */
public class JwtVerifier {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private JwtVerifier() {}

    /**
     * Verify whether the given secret key matches the JWT token's signature.
     *
     * @param token     Parsed JWT token
     * @param keyBytes  Secret key bytes (for HS family) or raw key material
     * @return true if the signature matches
     */
    public static boolean verifyHmac(JwtToken token, byte[] keyBytes) {
        String alg = token.getAlgorithm();
        if (alg == null) return false;

        String hmacAlg;
        switch (alg.toUpperCase()) {
            case "HS256": hmacAlg = "HmacSHA256"; break;
            case "HS384": hmacAlg = "HmacSHA384"; break;
            case "HS512": hmacAlg = "HmacSHA512"; break;
            default: return false;
        }

        try {
            Mac mac = Mac.getInstance(hmacAlg);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, hmacAlg);
            mac.init(secretKeySpec);
            byte[] computed = mac.doFinal(token.getSigningInput());
            return MessageDigest.isEqual(computed, token.getSignatureBytes());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify JWT with an RSA public key (RS256/384/512) or PSS (PS256/384/512).
     *
     * @param token      Parsed JWT token
     * @param publicKey  RSA public key
     * @return true if verification succeeds
     */
    public static boolean verifyRsa(JwtToken token, PublicKey publicKey) {
        String alg = token.getAlgorithm();
        if (alg == null) return false;

        try {
            Signature sig;
            switch (alg.toUpperCase()) {
                case "RS256": sig = Signature.getInstance("SHA256withRSA", "BC"); break;
                case "RS384": sig = Signature.getInstance("SHA384withRSA", "BC"); break;
                case "RS512": sig = Signature.getInstance("SHA512withRSA", "BC"); break;
                case "PS256": sig = Signature.getInstance("SHA256withRSAandMGF1", "BC"); break;
                case "PS384": sig = Signature.getInstance("SHA384withRSAandMGF1", "BC"); break;
                case "PS512": sig = Signature.getInstance("SHA512withRSAandMGF1", "BC"); break;
                default: return false;
            }
            sig.initVerify(publicKey);
            sig.update(token.getSigningInput());
            return sig.verify(token.getSignatureBytes());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify JWT with an RSA private key (sign and compare).
     */
    public static boolean verifyRsaWithPrivate(JwtToken token, PrivateKey privateKey) {
        String alg = token.getAlgorithm();
        if (alg == null) return false;

        try {
            Signature sig;
            switch (alg.toUpperCase()) {
                case "RS256": sig = Signature.getInstance("SHA256withRSA", "BC"); break;
                case "RS384": sig = Signature.getInstance("SHA384withRSA", "BC"); break;
                case "RS512": sig = Signature.getInstance("SHA512withRSA", "BC"); break;
                case "PS256": sig = Signature.getInstance("SHA256withRSAandMGF1", "BC"); break;
                case "PS384": sig = Signature.getInstance("SHA384withRSAandMGF1", "BC"); break;
                case "PS512": sig = Signature.getInstance("SHA512withRSAandMGF1", "BC"); break;
                default: return false;
            }
            sig.initSign(privateKey);
            sig.update(token.getSigningInput());
            byte[] computed = sig.sign();
            return MessageDigest.isEqual(computed, token.getSignatureBytes());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify JWT with an EC public key (ES256/384/512).
     */
    public static boolean verifyEc(JwtToken token, PublicKey publicKey) {
        String alg = token.getAlgorithm();
        if (alg == null) return false;

        try {
            Signature sig;
            switch (alg.toUpperCase()) {
                case "ES256": sig = Signature.getInstance("SHA256withECDSA", "BC"); break;
                case "ES384": sig = Signature.getInstance("SHA384withECDSA", "BC"); break;
                case "ES512": sig = Signature.getInstance("SHA512withECDSA", "BC"); break;
                default: return false;
            }
            sig.initVerify(publicKey);
            sig.update(token.getSigningInput());
            // JWT ES signatures are raw R||S format, need to convert to DER
            byte[] rawSig = token.getSignatureBytes();
            byte[] derSig = rawToDer(rawSig, alg.toUpperCase());
            return sig.verify(derSig);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify JWT with EC private key.
     * Since ECDSA is non-deterministic, we reconstruct the public key from the private key (Q = d*G).
     */
    public static boolean verifyEcWithPrivate(JwtToken token, PrivateKey privateKey) {
        try {
            // Use Bouncy Castle to multiply private scalar d by generator G to get public point Q
            // BCECPrivateKey provides getD() and access to curve params
            java.security.interfaces.ECPrivateKey ecPriv = (java.security.interfaces.ECPrivateKey) privateKey;

            // Use Bouncy Castle's KeyFactory to reconstruct key info
            org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey bcPriv =
                    (org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey) ecPriv;

            // getParameters() returns an ECNamedCurveParameterSpec instance
            org.bouncycastle.jce.spec.ECParameterSpec bcSpec = bcPriv.getParameters();
            org.bouncycastle.math.ec.ECPoint generator = bcSpec.getG();
            org.bouncycastle.math.ec.ECPoint pubPoint = generator.multiply(bcPriv.getD()).normalize();

            org.bouncycastle.jce.spec.ECPublicKeySpec pubKeySpec =
                    new org.bouncycastle.jce.spec.ECPublicKeySpec(pubPoint, bcSpec);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
            PublicKey pubKey = kf.generatePublic(pubKeySpec);
            return verifyEc(token, pubKey);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Convert raw R||S ECDSA signature to DER format required by Java's Signature API.
     */
    private static byte[] rawToDer(byte[] raw, String alg) {
        int componentLen;
        switch (alg) {
            case "ES256": componentLen = 32; break;
            case "ES384": componentLen = 48; break;
            case "ES512": componentLen = 66; break;
            default: componentLen = raw.length / 2;
        }

        byte[] r = Arrays.copyOfRange(raw, 0, componentLen);
        byte[] s = Arrays.copyOfRange(raw, componentLen, componentLen * 2);

        // Remove leading zeros but keep at least one byte
        r = trimLeadingZeros(r);
        s = trimLeadingZeros(s);

        // If high bit set, prepend 0x00
        if ((r[0] & 0x80) != 0) r = prependZero(r);
        if ((s[0] & 0x80) != 0) s = prependZero(s);

        int seqLen = 2 + r.length + 2 + s.length;
        byte[] der;
        if (seqLen <= 0x7F) {
            der = new byte[2 + seqLen];
            der[0] = 0x30;
            der[1] = (byte) seqLen;
            int pos = 2;
            der[pos++] = 0x02;
            der[pos++] = (byte) r.length;
            System.arraycopy(r, 0, der, pos, r.length); pos += r.length;
            der[pos++] = 0x02;
            der[pos++] = (byte) s.length;
            System.arraycopy(s, 0, der, pos, s.length);
        } else {
            der = new byte[3 + seqLen];
            der[0] = 0x30;
            der[1] = (byte) 0x81;
            der[2] = (byte) seqLen;
            int pos = 3;
            der[pos++] = 0x02;
            der[pos++] = (byte) r.length;
            System.arraycopy(r, 0, der, pos, r.length); pos += r.length;
            der[pos++] = 0x02;
            der[pos++] = (byte) s.length;
            System.arraycopy(s, 0, der, pos, s.length);
        }
        return der;
    }

    private static byte[] trimLeadingZeros(byte[] b) {
        int i = 0;
        while (i < b.length - 1 && b[i] == 0) i++;
        return Arrays.copyOfRange(b, i, b.length);
    }

    private static byte[] prependZero(byte[] b) {
        byte[] result = new byte[b.length + 1];
        result[0] = 0;
        System.arraycopy(b, 0, result, 1, b.length);
        return result;
    }
}
