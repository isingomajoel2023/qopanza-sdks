package com.qopanza.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Java client for the Qopanza API.
 *
 * Get a real API key first via {@code POST /v1/accounts} (signup) — this
 * client covers the crypto/analyze endpoints only, not account signup.
 * See examples/Quickstart.java for a worked example.
 *
 * <pre>{@code
 * QopanzaClient client = new QopanzaClient("http://localhost:8000", apiKey);
 * JsonNode kemKey = client.createKey("kem", "order-service-kem");
 * EncryptResult enc = client.encrypt(kemKey.get("id").asText(), "hello quantum-safe world".getBytes());
 * byte[] plaintext = client.decrypt(enc);
 * }</pre>
 */
public class QopanzaClient implements AutoCloseable {

    private final String baseUrl;
    private final String apiKey;
    private final OkHttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    public QopanzaClient(String baseUrl, String apiKey) {
        this.baseUrl = stripTrailingSlash(baseUrl) + "/v1";
        this.apiKey = apiKey;
        this.http = new OkHttpClient.Builder()
                .callTimeout(15, TimeUnit.SECONDS)
                .build();
    }

    // -- Keys -----------------------------------------------------------

    public JsonNode createKey(String purpose, String label) throws IOException {
        Map<String, Object> body = Map.of("purpose", purpose, "label", label == null ? "" : label);
        return request("POST", "/keys", body);
    }

    public JsonNode getKey(String keyId) throws IOException {
        return request("GET", "/keys/" + keyId, null);
    }

    // -- Encrypt / Decrypt ------------------------------------------------

    public static class EncryptResult {
        public String keyId;
        public String ciphertextKem;
        public String ciphertextPayload;
        public String nonce;
        public String backend;
    }

    public EncryptResult encrypt(String keyId, byte[] plaintext) throws IOException {
        Map<String, Object> body = Map.of(
                "key_id", keyId,
                "plaintext", Base64.getEncoder().encodeToString(plaintext)
        );
        JsonNode resp = request("POST", "/encrypt", body);

        EncryptResult result = new EncryptResult();
        result.keyId = resp.get("key_id").asText();
        result.ciphertextKem = resp.get("ciphertext_kem").asText();
        result.ciphertextPayload = resp.get("ciphertext_payload").asText();
        result.nonce = resp.get("nonce").asText();
        result.backend = resp.get("backend").asText();
        return result;
    }

    public byte[] decrypt(EncryptResult enc) throws IOException {
        Map<String, Object> body = Map.of(
                "key_id", enc.keyId,
                "ciphertext_kem", enc.ciphertextKem,
                "ciphertext_payload", enc.ciphertextPayload,
                "nonce", enc.nonce
        );
        JsonNode resp = request("POST", "/decrypt", body);
        return Base64.getDecoder().decode(resp.get("plaintext").asText());
    }

    // -- Sign / Verify ----------------------------------------------------

    public JsonNode sign(String keyId, byte[] message) throws IOException {
        Map<String, Object> body = Map.of(
                "key_id", keyId,
                "message", Base64.getEncoder().encodeToString(message)
        );
        return request("POST", "/sign", body);
    }

    public boolean verify(String keyId, byte[] message, String signature) throws IOException {
        Map<String, Object> body = Map.of(
                "key_id", keyId,
                "message", Base64.getEncoder().encodeToString(message),
                "signature", signature
        );
        JsonNode resp = request("POST", "/verify", body);
        return resp.get("valid").asBoolean();
    }

    // -- AI analysis --------------------------------------------------------

    public JsonNode analyze(Map<String, Object> context) throws IOException {
        Map<String, Object> body = Map.of("context", context);
        return request("POST", "/analyze", body);
    }

    // -- internals ----------------------------------------------------------

    private JsonNode request(String method, String path, Map<String, Object> body) throws IOException {
        Request.Builder builder = new Request.Builder()
                .url(baseUrl + path)
                .header("X-API-Key", apiKey);

        RequestBody reqBody = null;
        if (body != null) {
            reqBody = RequestBody.create(mapper.writeValueAsBytes(body), JSON);
        }

        switch (method) {
            case "GET" -> builder.get();
            case "POST" -> builder.post(reqBody != null ? reqBody : RequestBody.create(new byte[0], null));
            default -> throw new IllegalArgumentException("Unsupported method: " + method);
        }

        try (Response response = http.newCall(builder.build()).execute()) {
            String responseBody = response.body() != null ? response.body().string() : "";
            if (!response.isSuccessful()) {
                throw new QopanzaApiException(response.code(), responseBody);
            }
            return mapper.readTree(responseBody);
        }
    }

    private static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    @Override
    public void close() {
        http.dispatcher().executorService().shutdown();
        http.connectionPool().evictAll();
    }
}
