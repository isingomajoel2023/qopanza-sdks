package com.qopanza.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QopanzaApiExceptionTest {

    @Test
    void carriesStatusCodeAndBody() {
        QopanzaApiException ex = new QopanzaApiException(404, "{\"detail\":\"Key not found\"}");

        assertEquals(404, ex.getStatusCode());
        assertTrue(ex.getResponseBody().contains("Key not found"));
        assertTrue(ex.getMessage().contains("404"));
    }
}
