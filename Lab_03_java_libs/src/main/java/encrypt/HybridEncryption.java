package encrypt;

import helpers.FileHeader;
import helpers.Helpers;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * The abstract HybridEncryption class allows encrypting a document using hybrid
 * encryption and producing a MAC over a file header and the encrypted document.
 * GCM is also supported, but in this case, no MAC is created as this is
 * integrated in GCM. To use the class, a subclass must implement the five
 * abstract methods.
 */
public abstract class HybridEncryption {

    /**
     * Encrypts a document that is available from an InputStream.
     *
     * @param document The document to encrypt
     * @param cert The certificate of which the public key is used to encrypt
     * the document
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key lengtht to use
     * @param macAlgorithm The MAC algorithm to use
     * @param macPassword The password to use for the MAC
     * @return The encrypted document including the file header. Note: The
     * actual encryption is done when the returned stream is read.
     */
    public byte[] encryptDocumentStream(InputStream document, InputStream cert,
            String cipherAlgorithm, int keyLength, String macAlgorithm, byte[] macPassword) {

        // Generate a new random secret key
        byte[] secretKey = generateSecretKey(cipherAlgorithm, keyLength);

        // Encrypt the secret key with the public key in the certificate
        byte[] encryptedSecretKey = encryptSecretKey(secretKey, cert);

        // Generate the file header using the encrypted secret key
        FileHeader fileHeader = generateFileHeader(cipherAlgorithm, macAlgorithm, encryptedSecretKey);

        // Encrypt the document
        byte[] encryptedDocument = encryptDocument(document, fileHeader, secretKey);

        // Prepend the file header
        byte[] headerEncryptedDocument = concatByteArrays(fileHeader.encode(), encryptedDocument);

        // Compute the MAC
        byte[] headerEncryptedDocumentMAC;
        if (!Helpers.isGCM(cipherAlgorithm)) {
            byte[] hmac = computeMAC(headerEncryptedDocument, macAlgorithm, macPassword);

            // Append the MAC
            headerEncryptedDocumentMAC = concatByteArrays(headerEncryptedDocument, hmac);
        } else {
            headerEncryptedDocumentMAC = headerEncryptedDocument;
        }

        // Return the completely protected document
        return headerEncryptedDocumentMAC;
    }

    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length in bits
     * @return The secret key
     */
    protected abstract byte[] generateSecretKey(String cipherAlgorithm, int keyLength);

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey The secret key to encrypt
     * @param certificate An input stream from which the certificate with the
     * public key can be read.
     * @return The encrypted secret key
     */
    protected abstract byte[] encryptSecretKey(byte[] secretKey, InputStream certificate);

    /**
     * Creates a file header object and fills it with cipher and mac algorithms
     * names and an IV.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param macAlgorithm The MAC algorithm to use
     * @param encryptedSecretKey The encrypted secret key
     * @return The new file header object
     */
    protected abstract FileHeader generateFileHeader(String cipherAlgorithm, String macAlgorithm,
                                                     byte[] encryptedSecretKey);

    /**
     * Encrypts a document with a secret key. If GCM is used, the file header is
     * added as additionally encrypted data.
     *
     * @param document The document to encrypt
     * @param fileHeader The file header that contains information for
     * encryption
     * @param secretKey The secret key used for encryption
     * @return A byte array that contains the encrypted document
     */
    protected abstract byte[] encryptDocument(InputStream document,
                                              FileHeader fileHeader, byte[] secretKey);

    /**
     * Computes the HMAC over a byte array.
     *
     * @param macAlgorithm The MAC algorithm to use
     * @param password The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    protected abstract byte[] computeMAC(byte[] input, String macAlgorithm, byte[] password);

    private byte[] concatByteArrays(byte[] first, byte[] second) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(first);
            outputStream.write(second);
            return outputStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
