package ch.zhaw.securitylab.securefilestorage;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Common {
    
    // Server port
    public static final int PORT = 4567;
    
    // Supported reqiests
    public static final String LOGIN = "LOGIN";
    public static final String REGISTER = "REGISTER";
    public static final String GET = "GET";
    public static final String PUT = "PUT";
    public static final String SYSTEM = "SYSTEM";

    // Status messages
    public static final String OK = "OK";
    public static final String NOK = "NOK";
    
    // Control lines
    public static final String CONTENT = "-----CONTENT-----";
    public static final String DONE = "-----DONE-----";
    
    // The command to get disk usage
    public static final String COMMAND_USAGE = "USAGE";

    /* Converts a byte array to a hex string */
    public static String toHexString(byte bytes[]) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    
    /* Converts a hex string to a byte array */
    public static byte[] toByteArray(String hexString) {
        int len = hexString.length();
        byte[] bytes = new byte[len/2];
        for (int i = 0; i < len; i += 2) {
            bytes[i/2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + 
                                  Character.digit(hexString.charAt(i+1), 16));
        }
        return bytes;
    }
    
    /* Hashes an input 10000 times with SHA2-256 and returns the final hash as 
       a hex string */
    public static byte[] sha2_256_10000(byte[] input) {
        byte[] hash = input;
        try {
            MessageDigest hashFunction = MessageDigest.getInstance("SHA-256");
            for (int i=0; i < 10000; ++i) {
                hash = hashFunction.digest(hash);
            }
        } catch (NoSuchAlgorithmException e) {
        }
        return hash;
    }
}
