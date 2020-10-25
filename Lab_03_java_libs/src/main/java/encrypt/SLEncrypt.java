package encrypt;

import java.io.*;
import java.nio.charset.Charset;

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
        String plainText = "Lab_03_java_libs/src/main/resources/data/plain.txt";
        String cert = "Lab_03_java_libs/src/main/resources/data/certificate.cert";
        String password = "supersecret";

        String cipherAlgorithm = "AES/CBC/PKCS5Padding";
        String encrypted = "Lab_03_java_libs/src/main/resources/data/decrypted_AES_CBC_PKCS5Padding_128_HmacSHA256.txt";
        int keyLength = 128;
        String macAlgorithm = "HmacSHA256";
        new SLEncrypt(plainText, encrypted, cert, cipherAlgorithm, keyLength,macAlgorithm,password);

        cipherAlgorithm = "AES/GCM/NoPadding";
        encrypted = "Lab_03_java_libs/src/main/resources/data/decrypted_AES_GCM_NoPadding_192.txt";
        keyLength = 192;
        new SLEncrypt(plainText, encrypted, cert, cipherAlgorithm, keyLength,"",password);

        cipherAlgorithm = "AES/CTR/NoPadding";
        encrypted = "Lab_03_java_libs/src/main/resources/data/decrypted_AES_CTR_PKCS5Padding_256_HmacSHA1.txt";
        keyLength = 256;
        macAlgorithm = "HmacSHA1";
        new SLEncrypt(plainText, encrypted, cert, cipherAlgorithm, keyLength,macAlgorithm,password);

        cipherAlgorithm = "CHACHA20";
        encrypted = "Lab_03_java_libs/src/main/resources/data/decrypted_CHACHA20_256_HmacSHA3-512.txt";
        keyLength = 256;
        macAlgorithm = "HmacSHA3-512";
        new SLEncrypt(plainText, encrypted, cert, cipherAlgorithm, keyLength, macAlgorithm,password);

        cipherAlgorithm = "RC4";
        encrypted = "Lab_03_java_libs/src/main/resources/data/decrypted_RC4_128_HmacSHA3-256.txt";
        keyLength = 128;
        macAlgorithm = "HmacSHA3-256";
        new SLEncrypt(plainText, encrypted, cert, cipherAlgorithm, keyLength,macAlgorithm,password);
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
     * @param keyLengthString The key length in bits
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
     * @param macPassword The password to use for computing the HMAC
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
