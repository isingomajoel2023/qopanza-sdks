# qopanza (Java)

Java client for the Qopanza API.

## Build

```bash
cd sdks/java
mvn -q compile
```

## Usage

This SDK covers the crypto/analyze endpoints only — get a real API key by
signing up first (`POST /v1/accounts`, see the repo README or
`src/main/java/com/qopanza/sdk/examples/Quickstart.java` for a worked
example using OkHttp directly; account signup isn't part of the SDK yet):

```java
import com.qopanza.sdk.QopanzaClient;
import com.fasterxml.jackson.databind.JsonNode;

try (QopanzaClient client = new QopanzaClient("http://localhost:8000", apiKey)) {
    JsonNode kemKey = client.createKey("kem", "order-service-kem");

    byte[] plaintext = "hello quantum-safe world".getBytes();
    QopanzaClient.EncryptResult enc = client.encrypt(kemKey.get("id").asText(), plaintext);
    byte[] decrypted = client.decrypt(enc);

    JsonNode sigKey = client.createKey("signature", "order-service-sig");
    JsonNode signed = client.sign(sigKey.get("id").asText(), "order-42-confirmed".getBytes());
    boolean valid = client.verify(sigKey.get("id").asText(), "order-42-confirmed".getBytes(), signed.get("signature").asText());
}
```

Run the bundled example against a local stack:

```bash
mvn -q compile exec:java -Dexec.mainClass=com.qopanza.sdk.examples.Quickstart
```

(Add the `exec-maven-plugin` to `pom.xml` if you want `mvn exec:java` without
specifying the classpath manually — omitted here to keep the MVP pom minimal.)
