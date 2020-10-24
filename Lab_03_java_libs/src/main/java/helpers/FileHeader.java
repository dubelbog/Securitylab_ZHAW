package helpers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * The FileHeader class supports encoding and decoding of file headers. Encoding
 * means that the file header is built based on the version and encrypted
 * session key. Decoding means that a file header is read and the version and
 * encrypted session key are extracted.
 */
public class FileHeader {

    private static final byte[] FORMAT_STRING = {'S', 'L', 'C', 'R', 'Y', 'P', 'T'};
    private static final int VERSION = 1;
    private String cipherAlgorithm;
    private byte[] iv;
    private String macAlgorithm;
    private byte[] encryptedSecretKey;

    /**
     * Constructor. Empty default constructor.
     */
    public FileHeader() {
    }

    /**
     * Constructor. Decodes an existing file header that is stored in a byte
     * array. The values (version and encrypted session key) are written to the
     * instance variables version and encryptedSessionKey.
     *
     * @param fileHeader The file header to decode
     * @throws InvalidFormatException
     */
    public FileHeader(byte[] fileHeader) throws InvalidFormatException {
        decode(new ByteArrayInputStream(fileHeader));
    }

    /**
     * Constructor. Decodes an existing file header that can be read from an
     * InputStream. The values (version and encrypted session key) are written
     * to the instance variables version and encryptedSessionKey.
     *
     * @param fileHeaderStream The stream from which the file header can be read
     * @throws InvalidFormatException
     */
    public FileHeader(InputStream fileHeaderStream)
            throws InvalidFormatException {
        decode(fileHeaderStream);
    }

    /**
     * Decodes a file header that can be read from an InputStream. The values
     * (version and encrypted session key) are written to the instance variables
     * version and encryptedSessionKey.
     *
     * @param is The InputStream from which file header can be read
     * @throws InvalidFormatException
     */
    private void decode(InputStream is) throws InvalidFormatException {
        int tmpLen;
        byte[] formatString = new byte[FORMAT_STRING.length];

        try {
            // Read SLCrypt file type
            tmpLen = FORMAT_STRING.length;
            is.read(formatString);
            if (!Arrays.equals(FORMAT_STRING, formatString)) {
                throw new InvalidFormatException("Not an SLCrypt file");
            }

            // Read file version
            if (is.read() != VERSION) {
                throw new InvalidFormatException("Unknown file version");
            }

            // Read cipher
            tmpLen = is.read();
            byte[] cipherBytes = new byte[tmpLen];
            is.read(cipherBytes);
            cipherAlgorithm = new String(cipherBytes, Charset.forName("UTF-8"));

            // Read IV
            tmpLen = is.read();
            iv = new byte[tmpLen];
            is.read(iv);

            // Read MAC
            tmpLen = is.read();
            byte[] macBytes = new byte[tmpLen];
            is.read(macBytes);
            macAlgorithm = new String(macBytes, Charset.forName("UTF-8"));

            // Encrypted session key
            tmpLen = is.read();
            encryptedSecretKey = new byte[tmpLen];
            is.read(encryptedSecretKey);
        } catch (IOException e) {
            throw new InvalidFormatException("Invalid format");
        }
    }

    public String getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public void setCipherAlgorithm(String cipher) {
        this.cipherAlgorithm = cipher;
    }

    public byte[] getIV() {
        return iv;
    }

    public void setIV(byte[] iv) {
        this.iv = iv;
    }

    public String getMACAlgorithm() {
        return macAlgorithm;
    }

    public void setMACAlgorithm(String mac) {
        this.macAlgorithm = mac;
    }

    /**
     * Returns the encrypted session key.
     *
     * @return The encrypted session key
     */
    public byte[] getEncryptedSecretKey() {
        return encryptedSecretKey;
    }

    /**
     * Sets the encrypted session key.
     *
     * @param sessionKey The encrypted session key
     */
    public void setEncryptedSessionKey(byte[] sessionKey) {
        this.encryptedSecretKey = sessionKey;
    }

    /**
     * Encodes the file header using the currently stored values (version and
     * encrypted session key) from the instance variables version and
     * encryptedSessionKey.
     *
     * @return The file header
     */
    public byte[] encode() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        try {
            os.write(FORMAT_STRING);
            os.write(VERSION);
            os.write(cipherAlgorithm.length() & 0xff);
            os.write(cipherAlgorithm.getBytes(Charset.forName("UTF-8")));
            os.write(iv.length & 0xff);
            os.write(iv);
            os.write(macAlgorithm.length() & 0xff);
            os.write(macAlgorithm.getBytes(Charset.forName("UTF-8")));
            os.write(encryptedSecretKey.length & 0xff);
            os.write(encryptedSecretKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return os.toByteArray();
    }
}
