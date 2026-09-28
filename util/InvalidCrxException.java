package util;

/**
 * Thrown when a CRO0 file is invalid
 */
public class InvalidCrxException extends RuntimeException {

    /**
     * @param message The message to include in the exception
     */
    public InvalidCrxException(final String message) {
        super(message);
    }

    /**
     * @param message The message to include in the exception
     * @param cause The cause of the exception
     */
    public InvalidCrxException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
