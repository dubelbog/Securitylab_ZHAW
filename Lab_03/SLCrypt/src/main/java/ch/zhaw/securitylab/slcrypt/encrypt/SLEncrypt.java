package ch.zhaw.securitylab.slcrypt.encrypt;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import ch.zhaw.securitylab.slcrypt.Helpers;

/**
 * The main class to produce an encrypted and integrity-protected document.
 */
public class SLEncrypt {

    /**
     * The main method to hybrid encrypt a document.
     *
     * @param args The command line parameters
     */
    public static void main(String[] args) {
        if ((args.length < 5) || (args.length < 7 && !Helpers.isGCM(args[3]))) {
            System.out.println("Not enough arguments\n");
            usage();
        }
        new SLEncrypt(args[0], args[1], args[2], args[3], Integer.parseInt(args[4]),
                args.length < 6 ? "" : args[5], args.length < 7 ? "" : args[6]);
    }

    /**
     * Prints the usage.
     */
    public static void usage() {
        System.out.println("Usage: java SLEncrypt plain_file encrypted_file "
                + "certificate_file cipher_algorithm keylength [mac_algorithm mac_password]");
        System.exit(-1);
    }

    /**
     * Constructor. Hybrid encrypts a document.
     *
     * @param inFilename The file to encrypt
     * @param outFilename The filename to use for the encrypted document
     * @param certFilename The filename of the certificate
     * @param cipherAlgorithm The name of the cipher algorithm to use
     * @param keyLength The key length in bits
     * @param macAlgorithm The name of the mac algorithm to use
     * @param macPassword The password for the MAC
     */
    public SLEncrypt(String inFilename, String outFilename, String certFilename,
            String cipherAlgorithm, int keyLengthString, String macAlgorithm, String macPassword) {
        FileInputStream in = null;
        FileInputStream cert = null;
        FileOutputStream out = null;

        try {
            // create streams for all files to read/write
            File inFile = new File(inFilename);
            in = new FileInputStream(inFile);
            File outFile = new File(outFilename);
            out = new FileOutputStream(outFile);
            File keyFile = new File(certFilename);
            cert = new FileInputStream(keyFile);

            // encrypt the document
            encrypt(in, out, cert, cipherAlgorithm, keyLengthString, macAlgorithm, macPassword);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {

            // close the streams
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                }
            }
            if (cert != null) {
                try {
                    cert.close();
                } catch (IOException e) {
                }
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                }
            }
        }
    }

    /**
     * Hybrid encrypts a document.
     *
     * @param in The InputStream from which to read the document
     * @param out The OutputStream to which to write the encrypted document
     * @param cert The InputStream from which to read the certificate
     * @param cipherAlgorithm The name of the cipher algorithm to use
     * @param keyLength The key length in bits
     * @param macAlgorithm The name of the mac algorithm to use
     * @param mac_password The password to use for computing the HMAC
     * @throws IOException
     */
    public void encrypt(InputStream in, OutputStream out, InputStream cert,
            String cipherAlgorithm, int keyLength, String macAlgorithm, String macPassword)
            throws IOException {

        // hybrid encrypt the document
        HybridEncryption he = new HybridEncryptionImpl();
        byte[] encrypted = he.encryptDocumentStream(in, cert, cipherAlgorithm, keyLength,
                macAlgorithm, macPassword.getBytes(Charset.forName("UTF-8")));

        // save the encrypted document
        out.write(encrypted);
    }
}
