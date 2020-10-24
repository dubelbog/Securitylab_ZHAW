package decrypt;

import helpers.FileHeader;
import helpers.Helpers;
import helpers.InvalidFormatException;

import java.io.InputStream;
import java.util.Arrays;

/**
 * The abstract HybridDecryption class allows hybrid decryption of a document.
 * It provides implemented functionality to decrypt the document based on a
 * hybrid encrypted document and a private key (both available as InputStreams).
 * It also checks the MAC over the decrypted document. To use the class, a
 * subclass must implement the getFileHeader, getDecryptedSessionKey,
 * decryptDocument, and checkMAC methods.
 */
public abstract class HybridDecryption {

    public enum MACState {
        valid, invalid
    }

    /**
     * Decrypts an encrypted document that is available from an InputStream.
     *
     * @param input The document to decrypt
     * @param privateKey The private key corresponding to the public key that
     * was used to encrypt the document
     * @param macPassword The password to use for the MAC
     * @return The decrypted document
     */
    public DecryptedDocument decryptDocumentStream(InputStream input, InputStream privateKey,
                                                           byte[] macPassword) throws InvalidFormatException {

        DecryptedDocument decryptedDocument = new DecryptedDocument();

        // Get the file header
        byte[] headerEncryptedDocumentMAC = Helpers.inputStreamToByteArray(input);
        FileHeader fileHeader = getFileHeader(headerEncryptedDocumentMAC);

        // Get the MAC algorithm and check and remove the MAC if necessary
        byte[] headerEncryptedDocument;
        String macAlgorithm = fileHeader.getMACAlgorithm();
        if (macAlgorithm.length() > 0) {

            // Mac present, get headerEncryptedDocument and MAC
            int macLength = Helpers.getMACSize(macAlgorithm);
            headerEncryptedDocument = Arrays.copyOfRange(headerEncryptedDocumentMAC, 0,
                    headerEncryptedDocumentMAC.length - macLength);
            byte[] macReceived = Arrays.copyOfRange(headerEncryptedDocumentMAC,
                    headerEncryptedDocumentMAC.length - macLength, headerEncryptedDocumentMAC.length);
            decryptedDocument.setMacDoc(macReceived);
            if (checkMAC(decryptedDocument, headerEncryptedDocument,
                    macAlgorithm, macReceived, macPassword)) {
                decryptedDocument.setMacState(MACState.valid);
            } else {
                decryptedDocument.setMacState(MACState.invalid);
            }
        } else {

            // No MAC
            headerEncryptedDocument = headerEncryptedDocumentMAC;
            decryptedDocument.setMacDoc(new byte[0]);
            decryptedDocument.setMacComp(new byte[0]);
        }

        // Remove header from headerEncryptedDocument
        int headerLength = fileHeader.encode().length;
        byte[] encryptedDocument = Arrays.copyOfRange(headerEncryptedDocument,
                headerLength, headerEncryptedDocument.length);

        // Get the secret key from the file header and decrypt it
        byte[] secretKey = getDecryptedSecretKey(fileHeader, privateKey);

        // Decrypt the document with the secret key
        byte[] document = decryptDocument(encryptedDocument, fileHeader, secretKey);
        decryptedDocument.setDocument(document);

        // Set the fields in decryptedDocument and return it
        decryptedDocument.setCipherName(fileHeader.getCipherAlgorithm());
        decryptedDocument.setMACName(fileHeader.getMACAlgorithm());
        decryptedDocument.setIv(fileHeader.getIV());
        decryptedDocument.setSecretKey(secretKey);
        return decryptedDocument;
    }

    /**
     * Gets the file header object.
     *
     * @param headerEncryptedDocument The encrypted document, including the file
     * header
     * @return The file header object
     */
    protected abstract FileHeader getFileHeader(byte[] headerEncryptedDocument)
            throws InvalidFormatException;

    /**
     * Checks the HMAC over a byte array.
     *
     * @param decryptedDocument The object containing all results
     * @param input The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param expectedMAC The expected MAC
     * @return The byte array that contains the MAC
     */
    public abstract boolean checkMAC(DecryptedDocument decryptedDocument, byte[] input,
                                     String macAlgorithm, byte[] expectedMAC, byte[] password) throws InvalidFormatException;

    /**
     * Gets the decrypted secret key.
     *
     * @param fileHeader The file header
     * @param privateKey The private key to decrypt the secret key
     * @return The decrypted secret key
     */
    protected abstract byte[] getDecryptedSecretKey(FileHeader fileHeader,
                                                    InputStream privateKey) throws InvalidFormatException;

    /**
     * Decrypts the document.
     *
     * @param encryptedDocument The document to decrypt
     * @param fileHeader The file header that contains information for
     * encryption
     * @param secretKey The secret key to decrypt the document
     * @return The decrypted document
     */
    protected abstract byte[] decryptDocument(byte[] encryptedDocument,
                                              FileHeader fileHeader, byte[] secretKey) throws InvalidFormatException;
}
