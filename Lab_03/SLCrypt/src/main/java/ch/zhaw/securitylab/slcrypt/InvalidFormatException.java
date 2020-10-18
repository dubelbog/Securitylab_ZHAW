package ch.zhaw.securitylab.slcrypt;

/**
 * An InvalidFormatException is thrown whenever a format-related error occurs
 * during the en- or decryption process.
 *
 */
public class InvalidFormatException extends Exception {

    private static final long serialVersionUID = 5406225243905297855L;

    /**
     * Constructor. Creates an InvalidFormatException.
     *
     * @param reason The reason
     */
    public InvalidFormatException(String reason) {
        super(reason);
    }
}
