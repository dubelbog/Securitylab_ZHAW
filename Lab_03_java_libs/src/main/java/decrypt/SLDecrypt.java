package decrypt;

import helpers.Helpers;
import helpers.InvalidFormatException;

import java.io.*;
import java.nio.charset.Charset;

/**
 * The main class to hybrid decrypt (including checking the MAC) a document.
 */
public class SLDecrypt {

    /**
     * The main method to hybrid decrypt a document.
     *
     * @param args The command line parameters
     */
    public static void main(String[] args) {
        String fileIn = "Lab_03_java_libs/src/main/resources/data/decrypted_AES_CBC_PKCS5Padding_128_HmacSHA256.txt";
        String fileOut = "Lab_03_java_libs/src/main/resources/data/decrypted.txt";
        String keyFile = "Lab_03_java_libs/src/main/resources/data/private_key.pkcs8";
        String macPassword = "supersecret";
        System.out.println("-------- -------- -------- -------- -------- -------- -------- -------- --------");
        new SLDecrypt(fileIn, fileOut, keyFile, macPassword);

        fileIn = "Lab_03_java_libs/src/main/resources/data/decrypted_AES_GCM_NoPadding_192.txt";
        System.out.println("-------- -------- -------- -------- -------- -------- -------- -------- --------");
        new SLDecrypt(fileIn, fileOut, keyFile, macPassword);

        fileIn = "Lab_03_java_libs/src/main/resources/data/decrypted_AES_CTR_PKCS5Padding_256_HmacSHA1.txt";
        System.out.println("-------- -------- -------- -------- -------- -------- -------- -------- --------");
        new SLDecrypt(fileIn, fileOut, keyFile, macPassword);

        fileIn = "Lab_03_java_libs/src/main/resources/data/decrypted_CHACHA20_256_HmacSHA3-512.txt";
        System.out.println("-------- -------- -------- -------- -------- -------- -------- -------- --------");
        new SLDecrypt(fileIn, fileOut, keyFile, macPassword);

        fileIn = "Lab_03_java_libs/src/main/resources/data/decrypted_RC4_128_HmacSHA3-256.txt";
        System.out.println("-------- -------- -------- -------- -------- -------- -------- -------- --------");
        new SLDecrypt(fileIn, fileOut, keyFile, macPassword);
    }

    /**
     * Prints the usage.
     */
    public static void usage() {
        System.out.println("Usage: java SLDecrypt encrypted_file "
                + "decrypted_file private_key_file [mac_password]");
        System.exit(-1);
    }

    /**
     * Constructor. Hybrid decrypts a document.
     *
     * @param inFilename The file to decrypt
     * @param outFilename The filename to use for the decrypted document
     * @param keyFilename The filename of the private key
     * @param macPassword The password for the MAC
     */
    public SLDecrypt(String inFilename, String outFilename, String keyFilename, String macPassword) {
        FileInputStream in = null;
        FileInputStream key = null;
        FileOutputStream out = null;

        try {
            // create streams for all files to read/write
            File inFile = new File(inFilename);
            in = new FileInputStream(inFile);
            File outFile = new File(outFilename);
            out = new FileOutputStream(outFile);
            File keyFile = new File(keyFilename);
            key = new FileInputStream(keyFile);

            // decrypt the document	
            decrypt(in, out, key, macPassword);
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + e.getMessage());
        } catch (InvalidFormatException e) {
            System.out.println("Error decrypting file! " + e.getMessage());
        } catch (IOException e) {
            System.out.println("I/O error: " + e.getMessage());
        } finally {

            // close the streams
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                }
            }
            if (key != null) {
                try {
                    key.close();
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
     * Hybrid endecrypts a document.
     *
     * @param in The InputStream from which to read the encrypted document
     * @param out The OutputStream to which to write the decrypted document
     * @param key The InputStream from which to read the private key
     * @param mac_password The password to use for computing the HMAC
     * @throws IOException
     */
    public void decrypt(FileInputStream in, FileOutputStream out,
            FileInputStream key, String mac_password)
            throws InvalidFormatException, IOException {

        // hybrid decrypt the document
        HybridDecryption he = new HybridDecryptionImpl();
        DecryptedDocument document = he.decryptDocumentStream(in, key,
                mac_password.getBytes(Charset.forName("UTF-8")));

        // display information about MAC check if a MAC is used
        if (!Helpers.isGCM(document.getCipherName())) {
            System.out.println("MAC:       " + document.getMACName());
            System.out.println("MacDoc:    " + Helpers.asHex(document.getMacDoc()));
            System.out.println("MacComp:   " + Helpers.asHex(document.getMacComp()));

            if (document.getMacState() == HybridDecryption.MACState.valid) {
                System.out.println("MAC:       Successfully verified");
            } else if (document.getMacState() == HybridDecryption.MACState.invalid) {
                System.out.println("MAC:       Warning, wrong MAC!");
            }
        } else {
            System.out.println("MAC: No MAC, MAC is integrated in CGM");
        }

        // display information about algorithm, key and IV
        System.out.println("");
        System.out.println("Cipher:    " + document.getCipherName());
        System.out.println("Keylength: " + document.getSecretKey().length * 8);
        System.out.println("Key:       " + Helpers.asHex(document.getSecretKey()));
        System.out.println("IV:        " + Helpers.asHex(document.getIv()));

        // Display information about plaintext
        System.out.println("");
        System.out.print("Plaintext (" + document.getDocument().length + " bytes): ");
        if (document.getDocument().length <= 1000) {
            System.out.println(new String(document.getDocument()));
        } else {
            System.out.println(new String(document.getDocument(), 0, 1000));
        }

        // save the decrypted document
        out.write(document.getDocument());
    }
}
