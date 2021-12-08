package cn.gzten.jwt.exception;

public class AppException extends RuntimeException {
    private int httpStatusCode;
    public AppException(String message) {
        super(message);
    }

    public AppException(int httpStatusCode, String message) {
        this(message);
        this.httpStatusCode = httpStatusCode;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }
}
