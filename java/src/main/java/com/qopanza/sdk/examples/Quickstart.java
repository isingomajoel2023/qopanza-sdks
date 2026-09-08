package com.qopanza.sdk.examples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.qopanza.sdk.QopanzaClient;
import okhttp3.*;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Run against a local `docker compose up` stack:
 *   mvn -q compile exec:java -Dexec.mainClass=com.qopanza.sdk.examples.Quickstart
 *
 * Signs up for a fresh account to get a real API key first — this SDK
 * covers the crypto/analyze endpoints only, account signup isn't part of
 * it yet, so this example makes that one call directly with OkHttp.
 */
public class Quickstart {

    private static final String BASE_URL = "http://localhost:8000";

    private static String signUpAndGetApiKey() throws Exception {
        OkHttpClient http = new OkHttpClient();
        ObjectMapper mapper = new ObjectMapper();
        String body = mapper.writeValueAsString(Map.of(
                "email", "quickstart-java@example.com",
                "password", "quickstart-password-1"
        ));
        Request request = new Request.Builder()
                .url(BASE_URL + "/v1/accounts")
                .post(RequestBody.create(body, MediaType.get("application/json")))
                .build();
        try (Response response = http.newCall(request).execute()) {
            if (response.code() == 409) {
                throw new IllegalStateException(
                        "Account already exists — this quickstart signs up fresh each run. "
                                + "Change the email above or delete the account first.");
            }
            if (!response.isSuccessful()) {
                throw new IllegalStateException("Signup failed: " + response.code());
            }
            JsonNode json = mapper.readTree(response.body().string());
            return json.get("api_key").asText();
        }
    }

    public static void main(String[] args) throws Exception {
        String apiKey = signUpAndGetApiKey();

        try (QopanzaClient client = new QopanzaClient(BASE_URL, apiKey)) {

            System.out.println("== Key encapsulation (encrypt/decrypt) ==");
            JsonNode kemKey = client.createKey("kem", "quickstart-kem");
            System.out.println("Created KEM key: " + kemKey.get("id").asText());

            byte[] plaintext = "hello quantum-safe world".getBytes(StandardCharsets.UTF_8);
            QopanzaClient.EncryptResult enc = client.encrypt(kemKey.get("id").asText(), plaintext);
            byte[] decrypted = client.decrypt(enc);
            System.out.println("Round-trip OK: " + new String(decrypted, StandardCharsets.UTF_8).equals(new String(plaintext, StandardCharsets.UTF_8)));

            System.out.println("\n== Signatures ==");
            JsonNode sigKey = client.createKey("signature", "quickstart-sig");
            byte[] message = "order-42-confirmed".getBytes(StandardCharsets.UTF_8);
            JsonNode signed = client.sign(sigKey.get("id").asText(), message);
            boolean valid = client.verify(sigKey.get("id").asText(), message, signed.get("signature").asText());
            System.out.println("Signature valid: " + valid);

            System.out.println("\n== AI security analysis ==");
            JsonNode report = client.analyze(Map.of(
                    "algorithms_in_use", new String[]{"RSA-2048"},
                    "key_reuse_count", 3
            ));
            System.out.println("Summary: " + report.get("summary").asText());
            for (JsonNode finding : report.get("findings")) {
                System.out.println("  [" + finding.get("severity").asText() + "] "
                        + finding.get("rule_id").asText() + ": " + finding.get("title").asText());
            }
        }
    }
}
