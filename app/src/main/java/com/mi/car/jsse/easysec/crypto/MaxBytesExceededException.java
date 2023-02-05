package com.mi.car.jsse.easysec.crypto;

public class MaxBytesExceededException extends RuntimeCryptoException {
    public MaxBytesExceededException() {
    }

    public MaxBytesExceededException(String message) {
        super(message);
    }
}
