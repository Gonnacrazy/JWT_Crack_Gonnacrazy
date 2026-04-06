package com.jwtdecode.core;

import java.util.Base64;

/**
 * JWT Token parser - parses the three parts of a JWT token
 */
public class JwtToken {

    private final String rawToken;
    private final String headerPart;
    private final String payloadPart;
    private final String signaturePart;

    private String algorithm;
    private String headerJson;
    private String payloadJson;

    public JwtToken(String rawToken) {
        this.rawToken = rawToken.trim();
        String[] parts = this.rawToken.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format: expected 3 parts separated by dots, got " + parts.length);
        }
        this.headerPart = parts[0];
        this.payloadPart = parts[1];
        this.signaturePart = parts[2];
        parseHeader();
    }

    private void parseHeader() {
        try {
            byte[] headerBytes = Base64.getUrlDecoder().decode(padBase64(headerPart));
            this.headerJson = new String(headerBytes, java.nio.charset.StandardCharsets.UTF_8);
            // Simple extraction of "alg" field without extra JSON library dependency at this layer
            this.algorithm = extractJsonStringField(headerJson, "alg");
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decode JWT header: " + e.getMessage(), e);
        }
    }

    private String padBase64(String base64url) {
        String padded = base64url.replace('-', '+').replace('_', '/');
        int mod = padded.length() % 4;
        if (mod == 2) padded += "==";
        else if (mod == 3) padded += "=";
        return padded;
    }

    /**
     * Extracts a string field value from a simple JSON string.
     */
    private String extractJsonStringField(String json, String fieldName) {
        // Pattern: "fieldName":"value"
        String searchKey = "\"" + fieldName + "\"";
        int keyIdx = json.indexOf(searchKey);
        if (keyIdx < 0) return null;
        int colonIdx = json.indexOf(':', keyIdx + searchKey.length());
        if (colonIdx < 0) return null;
        // Skip whitespace
        int valueStart = colonIdx + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) valueStart++;
        if (valueStart >= json.length()) return null;
        if (json.charAt(valueStart) != '"') return null;
        int valueEnd = json.indexOf('"', valueStart + 1);
        if (valueEnd < 0) return null;
        return json.substring(valueStart + 1, valueEnd);
    }

    public String getRawToken() {
        return rawToken;
    }

    public String getHeaderPart() {
        return headerPart;
    }

    public String getPayloadPart() {
        return payloadPart;
    }

    public String getSignaturePart() {
        return signaturePart;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getHeaderJson() {
        return headerJson;
    }

    /**
     * Lazily decode payload
     */
    public String getPayloadJson() {
        if (payloadJson == null) {
            try {
                byte[] payloadBytes = Base64.getUrlDecoder().decode(padBase64(payloadPart));
                payloadJson = new String(payloadBytes, java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception e) {
                payloadJson = "(decode error: " + e.getMessage() + ")";
            }
        }
        return payloadJson;
    }

    /**
     * Returns the signing input (header.payload) as bytes
     */
    public byte[] getSigningInput() {
        String signingInput = headerPart + "." + payloadPart;
        return signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Returns the decoded signature bytes
     */
    public byte[] getSignatureBytes() {
        // JWT signature is base64url encoded (no padding)
        String sig = signaturePart.replace('-', '+').replace('_', '/');
        int mod = sig.length() % 4;
        if (mod == 2) sig += "==";
        else if (mod == 3) sig += "=";
        return Base64.getDecoder().decode(sig);
    }

    @Override
    public String toString() {
        return "JwtToken{alg=" + algorithm + ", header=" + headerJson + "}";
    }
}
