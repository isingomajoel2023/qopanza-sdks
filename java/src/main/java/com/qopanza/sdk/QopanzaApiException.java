package com.qopanza.sdk;

/** Thrown when the Qopanza API returns a non-2xx response. */
public class QopanzaApiException extends RuntimeException {
    private final int statusCode;
    private final String responseBody;

    public QopanzaApiException(int statusCode, String responseBody) {
        super("Qopanza API error [" + statusCode + "]: " + responseBody);
        this.statusCode = statusCode;
        this.responseBody = responseBody;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getResponseBody() {
        return responseBody;
    }
}
