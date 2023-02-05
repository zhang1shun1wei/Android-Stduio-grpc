package com.mi.car.jsse.easysec.crypto.io;

public class InvalidCipherTextIOException extends CipherIOException {
    private static final long serialVersionUID = 1;

    public InvalidCipherTextIOException(String message, Throwable cause) {
        super(message, cause);
    }
}
