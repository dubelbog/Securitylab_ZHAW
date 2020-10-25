package encrypt;

import helpers.FileHeader;
import helpers.Helpers;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.List;

/**
 * A concrete implementation of the abstract class HybridEncryption.
 */
public class HybridEncryptionImpl extends HybridEncryption {

    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength       The key length in bits
     * @return The secret key
     */
    @Override
    protected byte[] generateSecretKey(String cipherAlgorithm, int keyLength) {
        SecretKey secretKey = null;
        if (isCipherAlgorithmAndKeyLengthSupported(cipherAlgorithm, keyLength)) {
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(Helpers.getCipherName(cipherAlgorithm));
                keyGenerator.init(keyLength);
                secretKey = keyGenerator.generateKey();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Kombination of cipher algorithm and key length is not supported. Please check your parameters.");
        }
        return secretKey != null ? secretKey.getEncoded() : null;
    }

    private boolean isCipherAlgorithmAndKeyLengthSupported(String cipherAlgorithm, int keyLength) {
        List<String> supportedAlgorithms = Arrays.asList("AES/CBC/PKCS5Padding", "AES/GCM/NoPadding",
                "AES/CTR/NoPadding", "RC4", "CHACHA20");
        boolean isSupportedAlgorithm = supportedAlgorithms.stream().anyMatch(algorithm -> algorithm.equals(cipherAlgorithm));
        boolean isSupportedKeyLength;
        if (cipherAlgorithm.equals("RC4")) {
            isSupportedKeyLength = keyLength == 128;
        } else {
            isSupportedKeyLength = keyLength == 128 || keyLength == 192 || keyLength == 256;
        }
        return isSupportedAlgorithm && isSupportedKeyLength;
    }

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey   The secret key to encrypt
     * @param certificate An input stream from which the certificate with the
     *                    public key can be read.
     * @return The encrypted secret key
     */
    @Override
    protected byte[] encryptSecretKey(byte[] secretKey, InputStream certificate) {

        byte[] encryptedKey = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate cert = certificateFactory.generateCertificate(certificate);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.ENCRYPT_MODE, cert);
            encryptedKey = cipher.doFinal(secretKey);

        } catch (CertificateException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return encryptedKey;
    }

    /**
     * Creates a file header object and fills it with cipher and mac algorithms
     * names and an IV.
     *
     * @param cipherAlgorithm    The cipher algorithm to use
     * @param macAlgorithm       The MAC algorithm to use
     * @param encryptedSecretKey The encrypted secret key
     * @return The new file header object
     */
    @Override
    protected FileHeader generateFileHeader(String cipherAlgorithm, String macAlgorithm,
                                            byte[] encryptedSecretKey) {

        FileHeader fileHeader = new FileHeader();
        fileHeader.setCipherAlgorithm(cipherAlgorithm);
        SecureRandom secureRandom = new SecureRandom();
        fileHeader.setIV(secureRandom.generateSeed(Helpers.getIVLength(cipherAlgorithm)));
        fileHeader.setMACAlgorithm(macAlgorithm);
        fileHeader.setEncryptedSessionKey(encryptedSecretKey);
        return fileHeader;
    }

    /**
     * Encrypts a document with a secret key. If GCM is used, the file header is
     * added as additionally encrypted data.
     *
     * @param document   The document to encrypt
     * @param fileHeader The file header that contains information for
     *                   encryption
     * @param secretKey  The secret key used for encryption
     * @return A byte array that contains the encrypted document
     */
    @Override
    protected byte[] encryptDocument(InputStream document, FileHeader fileHeader, byte[] secretKey) {

        byte[] ciphertext = null;
        try {
            if (isCipherAlgorithmAndKeyLengthSupported(fileHeader.getCipherAlgorithm(), fileHeader.getEncryptedSecretKey().length)) {
                String cipherAlgorithm = fileHeader.getCipherAlgorithm();
                byte[] iv = fileHeader.getIV();
                Cipher cipher = Cipher.getInstance(cipherAlgorithm);
                SecretKeySpec keySpec = new SecretKeySpec(secretKey, Helpers.getCipherName(cipherAlgorithm));

                if (Helpers.isGCM(cipherAlgorithm)) {
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
                    cipher.updateAAD(fileHeader.encode());
                } else if (Helpers.isCHACHA20(cipherAlgorithm)) {
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, new ChaCha20ParameterSpec(iv, 1));
                } else if (Helpers.hasIV(cipherAlgorithm)) {
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                }

                CipherInputStream cipherInputStream = new CipherInputStream(document, cipher);

                byte[] buffer = new byte[8192];
                int bytesRead;
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                    output.write(buffer, 0, bytesRead);
                }
                ciphertext = output.toByteArray();
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException
                | NoSuchPaddingException | IOException e) {
            e.printStackTrace();
        }
        return ciphertext;
    }

    /**
     * Computes the HMAC over a byte array.
     *
     * @param dataToProtect The input over which to compute the MAC
     * @param macAlgorithm  The MAC algorithm to use
     * @param password      The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    @Override
    protected byte[] computeMAC(byte[] dataToProtect, String macAlgorithm, byte[] password) {
        byte[] hmac = null;
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(new SecretKeySpec(password, macAlgorithm));
            hmac = mac.doFinal(dataToProtect);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return hmac;
    }
}
