package ch.zhaw.securitylab.tlstester;

import java.security.Security;

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

    /**
     * The run method that executes all tests: Check if the server can be
     * reached; print which SSL/TLS versions are supported and which are not;
     * print the certificate chain including details about the certificates;
     * check which cipher suites the server supports per SSL/TLS protocol
     * version and list them separated in secure and insecure ones.
     *
     * @throws Exception An exception occurred
     */
    private void run() throws Exception {

        // To be implemented
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
}
