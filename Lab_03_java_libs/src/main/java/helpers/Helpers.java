package helpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * The Helpers class contains a collection of useful helpers.
 */
public class Helpers {

    public static final int AUTH_TAG_LENGTH = 128;

    /**
     * Returns the hexadecimal representation of the elements in a byte array.
     *
     * @param buf The byte array to convert
     * @return The hexadecimal representation as a String
     */
    public static String asHex(byte buf[]) {
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10) {
                strbuf.append("0");
            }
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        return strbuf.toString();
    }

    /**
     * Converts an input stream to a byte array
     *
     * @param input The input stream
     * @return A byte array containing the data
     */
    public static byte[] inputStreamToByteArray(InputStream input) {
        byte[] buffer = new byte[8192];
        int bytesRead;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
            return output.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * returns the byte length of MAC algorithm
     *
     * @param macAlgorithm The mac algorithm
     * @return The number of bytes
     */
    public static int getMACSize(String macAlgorithm) {
        switch (macAlgorithm.toUpperCase()) {
            case "HMACMD5":
                return 16;
            case "HMACSHA1":
                return 20;
            case "HMACSHA224":
                return 28;
            case "HMACSHA256":
            case "HMACSHA3-256":
                return 32;
            case "HMACSHA512":
            case "HMACSHA3-512":
                return 64;
            default:
                return 0;
        }
    }

    /**
     * Checks if the cipher uses the CBC mode
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If CBC is used or not
     */
    public static boolean isCBC(String cipherAlgorithm) {
        return cipherAlgorithm.toUpperCase().contains("/CBC");
    }

    /**
     * Checks if the cipher uses the GCM mode
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If CBC is used or not
     */
    public static boolean isGCM(String cipherAlgorithm) {
        return cipherAlgorithm.toUpperCase().contains("/GCM");
    }

    /**
     * Checks if the cipher uses the CTR mode
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If CBC is used or not
     */
    public static boolean isCTR(String cipherAlgorithm) {
        return cipherAlgorithm.toUpperCase().contains("/CTR"); 
    }
    
    /**
     * Checks if the cipher is CHACHA20
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If thh cipher ids CHACHA20 or not
     */
    public static boolean isCHACHA20(String cipherAlgorithm) {
        return cipherAlgorithm.toUpperCase().equals("CHACHA20");
    }
    
    /**
     * Checks if the cipher uses an IV
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If an IV is used or not
     */
    public static boolean hasIV(String cipherAlgorithm) {
        return (isCBC(cipherAlgorithm) || isGCM(cipherAlgorithm) || 
                isCTR(cipherAlgorithm) || isCHACHA20(cipherAlgorithm));
    }

    /**
     * Returns the raw cipher name
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return The cipher name (e.g. AES)
     */
    public static String getCipherName(String cipherAlgorithm) {
        return cipherAlgorithm.split("/")[0];
    }

    /**
     * Returns the IV length in bytes
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return The length of the IV in bytes
     */
    public static int getIVLength(String cipherAlgorithm) {
        if (hasIV(cipherAlgorithm)) {
            if (getCipherName(cipherAlgorithm).toUpperCase().contains("DES")) {
                return 8;
            } else if (isCHACHA20(cipherAlgorithm)) {
                return 12;
            } else {
                return 16;
            }
        }
        return 0;
    }
}