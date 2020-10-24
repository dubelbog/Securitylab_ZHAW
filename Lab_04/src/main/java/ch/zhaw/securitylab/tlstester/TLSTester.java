package ch.zhaw.securitylab.tlstester;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This class serves to test SSL/TLS servers.
 *
 * @author Marc Rennhard
 */
public class TLSTester {

    // Variables specified via the command line parameters
    private static String host;
    private static int port;
    private static String trustStore = null;
    private static String password = null;
    private String cipherSuitesSupport = "";
    private ArrayList<String> supportedProtocols = new ArrayList<>();

    /**
     * The run method that executes all tests: Check if the server can be
     * reached; print which SSL/TLS versions are supported and which are not;
     * print the certificate chain including details about the certificates;
     * check which cipher suites the server supports per SSL/TLS protocol
     * version and list them separated in secure and insecure ones.
     *
     * @throws Exception An exception occurred
     */
    public void run() throws Exception {
        // To be implemented

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        if (trustStore == null) {
            tmf.init((KeyStore) null);
            X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];
            X509Certificate[] trustedCerts = tm.getAcceptedIssuers();
            System.out.println("Use default truststore with " + trustedCerts.length + " certificates.");
            sslContext.init(null, tmf.getTrustManagers(), null);
        } else {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");

            keyStore.load(new FileInputStream("/Users/bdubel/Documents/ZHAW/HS_2020/SWS/SWS1_Labs_2020/Lab_04/src/main/resources/"+ trustStore), password.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(keyStore, password.toCharArray());

            tmf.init(keyStore);
            X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];
            X509Certificate[] trustedCerts = tm.getAcceptedIssuers();
            System.out.println("Use specified truststore ("+trustStore +") with " + trustedCerts.length + " certificates.");
            sslContext.init(null, new TrustManager[] {new CustomX509TrustManager()}, null);
        }

        SSLSocketFactory sslSF = (SSLSocketFactory)sslContext.getSocketFactory();
        List<String> ciphers;

        try{
            System.out.print("Check connectivity to " + host + ":" + port + " - ");
            SSLSocket sslSocket = (SSLSocket)sslSF.createSocket(host, port);
            System.out.println("OK.");
            ciphers = getSupportedCipherSuitesAndSetPrefix(sslSocket);
            sslSocket.close();

        } catch(Exception e) {
            System.out.println("FAILED.");
            throw e;
        }

        System.out.println();

        List<String> protocols = Arrays.asList("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3");
        protocols.forEach(protocol -> getSupportedProtocols(protocol,sslSF));
        System.out.println();

        SSLSocket sslSocket = (SSLSocket)sslSF.createSocket(host, port);
        SSLSession session = sslSocket.getSession();
        X509Certificate[] certificates = (X509Certificate[])session.getPeerCertificates();


        List<X509Certificate> certs = Arrays.asList(certificates);

        X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];
        X509Certificate[] trustedCerts = tm.getAcceptedIssuers();
        List<X509Certificate> trustedCertificates = Arrays.asList(trustedCerts);
        int size = certs.size();
        checkRootCert(trustedCertificates,certificates,size);
        Collections.reverse(certs);
        certs.forEach(cert -> getCertificatesInfos(cert, certs.indexOf(cert)+1));
        sslSocket.close();
        System.out.println(cipherSuitesSupport);
        printSupportedCipherSuites(getSupportedCipherSuits(sslSF, ciphers));

    }

    private void checkRootCert(List<X509Certificate> trustedCertificates, X509Certificate[] certificates, int size) {
        X509Certificate root = trustedCertificates.stream()
                .filter(cert -> cert.getSubjectDN().equals(certificates[certificates.length - 1]
                .getIssuerDN()))
                .findAny().orElseGet(null);

        if (root != null) {
            size++;
            System.out.println("The root CA is trusted");
            System.out.println();
        } else {
            System.out.println("The root CA is not trusted, ignore root CA checks in this test");
        }

        System.out.println(size + " certificate(s) in chain");
        if (root != null) {
            getCertificatesInfos(root, 0);
        }
    }

    private void printSupportedCipherSuites(HashMap<String, ArrayList<CipherSuit>> ciphersProtocolsMap) {
        printSupportedSecureCipherSuites(ciphersProtocolsMap);
        printSupportedInSecureCipherSuites(ciphersProtocolsMap);
    }

    private void printSupportedSecureCipherSuites(HashMap<String, ArrayList<CipherSuit>> ciphersProtocolsMap) {
        HashSet<CipherSuit> suitsSecure = new HashSet<>();
        System.out.println("The following SECURE cipher suites are supported by the server:");
        System.out.println();
        ciphersProtocolsMap.forEach((protocol, cipherSuites) -> {
            List<CipherSuit> ciphers = Arrays.asList(cipherSuites.stream().filter(CipherSuit::isSecure).toArray(CipherSuit[]::new));
            suitsSecure.addAll(ciphers);
            if (suitsSecure.size() > 0) {
                System.out.println(protocol + ": " + suitsSecure.size() + " cipher suite(s):");
            }
            suitsSecure.forEach(cipherSuit -> System.out.println(cipherSuit.name));
            System.out.println();
        });

        System.out.println("TOTAL UNIQUE SECURE cipher suites: " + suitsSecure.size());
        System.out.println();
    }

    private void printSupportedInSecureCipherSuites(HashMap<String, ArrayList<CipherSuit>> ciphersProtocolsMap) {
        HashSet<CipherSuit> suitsInsecure = new HashSet<>();
        System.out.println("The following INSECURE cipher suites are supported by the server:");
        System.out.println();
        ciphersProtocolsMap.forEach((protocol, cipherSuites) -> {
            List<CipherSuit> ciphers = Arrays.asList(cipherSuites.stream().filter(cipherSuit -> !cipherSuit.isSecure()).toArray(CipherSuit[]::new));
            suitsInsecure.addAll(ciphers);
            if (suitsInsecure.size() > 0) {
                System.out.println(protocol + ": " + suitsInsecure.size() + " cipher suite(s):");
            }
            suitsInsecure.forEach(cipherSuit -> System.out.println(cipherSuit.name));
            System.out.println();
        });
        System.out.println("TOTAL UNIQUE INSECURE cipher suites: " + suitsInsecure.size());
        System.out.println();
    }

    private List<String> getSupportedCipherSuitesAndSetPrefix(SSLSocket sslSocket) {
        String[] cipherSuites = sslSocket.getSupportedCipherSuites();
        cipherSuitesSupport = cipherSuitesSupport.concat("\nCheck supported cipher suites (test program supports " + cipherSuites.length +
                " cipher suites) \nDONE... \n"
                + cipherSuites.length +" cipher suites using 3 SSL/TLS protocol versions tested\n");
        return Arrays.asList(cipherSuites);
    }

    private HashMap<String, ArrayList<CipherSuit>> getSupportedCipherSuits(SSLSocketFactory sslSF, List<String> cipherSuites) {
        HashMap<String, ArrayList<CipherSuit>> ciphersProtocolsMap = new HashMap<>();
        supportedProtocols.forEach(protocol -> {
            ArrayList<CipherSuit> ciphers = new ArrayList<>();
                cipherSuites.forEach(cipherSuite -> {
                    try {
                        SSLSocket sslSocket = (SSLSocket)sslSF.createSocket(host, port);
                        sslSocket.setEnabledProtocols(new String[] {protocol});
                        sslSocket.setEnabledCipherSuites(new String[] {cipherSuite});
                        sslSocket.startHandshake();
                        ciphers.add(new CipherSuit(cipherSuite, isCipherSuitSecure(cipherSuite)));
                        sslSocket.close();
                    } catch (IOException e) {
                        System.out.print("");
                    }
                });
            ciphersProtocolsMap.put(protocol, ciphers);
        });

        return ciphersProtocolsMap;
    }

    private boolean isCipherSuitSecure(String cipherSuite) {
//        return StringUtils.indexOfAny(cipherSuite, new String[]{"RC4", "DES", "3DES", "MD5"}) == -1;
        boolean isKeyLengthSecure = true;
        boolean isMacSecure = true;
        boolean isCipherSecure = !(cipherSuite.contains("RC4") || cipherSuite.contains("DES") || cipherSuite.contains("3DES"));
        String[] split = cipherSuite.split("_");
        if(split.length > 0) {
            List<String> numbers= Arrays.stream(split).filter(word -> word.matches("\\d+(\\.\\d+)?")).collect(Collectors.toList());
            if (numbers.size() > 0) {
                isKeyLengthSecure = Integer.parseInt(numbers.get(0)) >= 128;
            }
            isMacSecure = !split[split.length -1].contains("MD5");
        }
        return isCipherSecure && isKeyLengthSecure && isMacSecure;
    }

    private void getSupportedProtocols(String protocol, SSLSocketFactory sslSF) {
        try {
            System.out.print(protocol + " : ");
            SSLSocket sslSocket = (SSLSocket)sslSF.createSocket(host, port);
            sslSocket.setEnabledProtocols(new String[] {protocol});
            sslSocket.startHandshake();
            supportedProtocols.add(protocol);
            System.out.println("Yes");
            sslSocket.close();
        } catch (Exception e) {
            System.out.println("No");
        }
    }

    private void getCertificatesInfos(X509Certificate cert, int nr) {
        System.out.println();
        System.out.println("Certificate " + nr);
        System.out.println("Subject: " + cert.getSubjectDN().getName());
        System.out.println("Issuer: " + cert.getIssuerDN().getName());
        System.out.println("Validity: " + cert.getNotBefore() + " - " + cert.getNotAfter());
        System.out.println("Algorithm: " + cert.getSigAlgName());
        if(cert.getPublicKey() instanceof ECPublicKey) {
            System.out.println("EC public key length: " + ((ECPublicKey) cert.getPublicKey()).getParams().getOrder().bitLength());
        } else {
            System.out.println("RSA public key length: " + ((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength());
        }
    }

    /**
     * The main method.
     *
     * @param argv The command line parameters
     * @throws Exception If an exception occurred
     */
    public static void main(String argv[]) throws Exception {
        
        // This is required to enable SSLv3
        Security.setProperty("jdk.tls.disabledAlgorithms", "");

        // Create a TLSTester object, and execute the test
        try {
            host = argv[0];
            port = Integer.parseInt(argv[1]);
            if ((port < 1) || (port > 65535)) {
                throw (new Exception());
            }
            if (argv.length > 2) {
                trustStore = argv[2];
                password = argv[3];
            }
        } catch (Exception e) {
            System.out.println("\nUsage: java TLSTester host port {truststore password}\n");
            System.exit(0);
        }
        TLSTester tlst = new TLSTester();
        tlst.run();
    }

    private static class CipherSuit {

        private String name;
        private boolean secure;

        public CipherSuit(String name, boolean secure) {
            this.name = name;
            this.secure = secure;
        }

        public boolean isSecure() {
            return secure;
        }
    }

    private static class CustomX509TrustManager implements X509TrustManager {

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
}
