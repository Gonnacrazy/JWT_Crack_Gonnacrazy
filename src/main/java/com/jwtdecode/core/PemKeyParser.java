package com.jwtdecode.core;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * PEM key parser - parses public and private keys from PEM format strings.
 * Supports RSA, EC key types used in RS/PS/ES JWT algorithms.
 */
public class PemKeyParser {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private PemKeyParser() {}

    /**
     * Parse result holding either a public key or private key (or both).
     */
    public static class ParsedKey {
        public final PublicKey publicKey;
        public final PrivateKey privateKey;
        public final String keyType; // "PUBLIC", "PRIVATE", "KEYPAIR"

        public ParsedKey(PublicKey publicKey, PrivateKey privateKey, String keyType) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.keyType = keyType;
        }
    }

    /**
     * Parse a PEM string (possibly containing multiple keys on one line with \\n or actual newlines).
     * Dictionary entries for PEM certs look like:
     * -----BEGIN PUBLIC KEY-----MIIBIjANBg...-----END PUBLIC KEY-----
     *
     * @param pemLine A single line from the dictionary that represents a PEM cert
     * @return ParsedKey or null if parsing fails
     */
    public static ParsedKey parse(String pemLine) {
        if (pemLine == null || pemLine.isBlank()) return null;

        // Normalize: replace literal \n with actual newlines
        String pem = pemLine.replace("\\n", "\n").trim();

        // If it doesn't look like a PEM header, skip
        if (!pem.contains("-----BEGIN ")) return null;

        try {
            PEMParser parser = new PEMParser(new StringReader(pem));
            Object obj = parser.readObject();
            parser.close();

            if (obj == null) return null;

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
                // BEGIN PUBLIC KEY
                PublicKey pub = converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) obj);
                return new ParsedKey(pub, null, "PUBLIC");

            } else if (obj instanceof PEMKeyPair) {
                // BEGIN RSA PRIVATE KEY / BEGIN EC PRIVATE KEY (PKCS#1)
                KeyPair kp = converter.getKeyPair((PEMKeyPair) obj);
                return new ParsedKey(kp.getPublic(), kp.getPrivate(), "KEYPAIR");

            } else if (obj instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
                // Encrypted private key - skip (no password)
                return null;

            } else if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                // BEGIN PRIVATE KEY (PKCS#8)
                PrivateKey priv = converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) obj);
                return new ParsedKey(null, priv, "PRIVATE");

            } else if (obj instanceof X509CertificateHolder) {
                // X.509 certificate - extract public key
                java.security.cert.X509Certificate cert =
                        new JcaX509CertificateConverter().setProvider("BC")
                                .getCertificate((X509CertificateHolder) obj);
                return new ParsedKey(cert.getPublicKey(), null, "PUBLIC");
            }

        } catch (Exception e) {
            // Parse failed - not a valid PEM
        }
        return null;
    }
}
