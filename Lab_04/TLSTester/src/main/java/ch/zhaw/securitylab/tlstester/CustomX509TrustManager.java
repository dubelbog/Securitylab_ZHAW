package ch.zhaw.securitylab.tlstester;

import javax.net.ssl.X509TrustManager;

/**
 * Custom TrustManager that ignores all certificate errors
 */
public class CustomX509TrustManager implements X509TrustManager {

    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        // Empty as returning without throwing an exception means the  check succeeded
    }

    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        // Empty as returning without throwing an exception means the  check succeeded
    }
}
