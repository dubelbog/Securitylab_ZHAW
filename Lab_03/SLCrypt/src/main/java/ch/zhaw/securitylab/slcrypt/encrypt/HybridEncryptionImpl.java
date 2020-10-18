package ch.zhaw.securitylab.slcrypt.encrypt;

import java.io.InputStream;
import ch.zhaw.securitylab.slcrypt.FileHeader;

/**
 * A concrete implementation of the abstract class HybridEncryption.
 */
public class HybridEncryptionImpl extends HybridEncryption {

    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length in bits
     * @return The secret key
     */
    @Override
    protected byte[] generateSecretKey(String cipherAlgorithm, int keyLength) {

        // To do...
        return null;
    }

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey The secret key to encrypt
     * @param certificate An input stream from which the certificate with the
     * public key can be read.
     * @return The encrypted secret key
     */
    @Override
    protected byte[] encryptSecretKey(byte[] secretKey, InputStream certificate) {

        // To do...
        return null;
    }

    /**
     * Creates a file header object and fills it with cipher and mac algorithms
     * names and an IV.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param macAlgorithm The MAC algorithm to use
     * @param encryptedSecretKey The encrypted secret key
     * @return The new file header object
     */
    @Override
    protected FileHeader generateFileHeader(String cipherAlgorithm, String macAlgorithm,
            byte[] encryptedSecretKey) {

        // To do...
        return null;
    }

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
    @Override
    protected byte[] encryptDocument(InputStream document, FileHeader fileHeader, byte[] secretKey) {

        // To do...
        return null;
    }

    /**
     * Computes the HMAC over a byte array.
     *
     * @param dataToProtect The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param password The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    @Override
    protected byte[] computeMAC(byte[] dataToProtect, String macAlgorithm, byte[] password) {

        // To do...
        return null;
    }
}
