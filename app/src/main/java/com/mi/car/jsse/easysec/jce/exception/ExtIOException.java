package com.mi.car.jsse.easysec.jce.exception;

import java.io.IOException;

public class ExtIOException extends IOException implements ExtException {
    private Throwable cause;

    public ExtIOException(String message, Throwable cause2) {
        super(message);
        this.cause = cause2;
    }

    @Override // com.mi.car.jsse.easysec.jce.exception.ExtException
    public Throwable getCause() {
        return this.cause;
    }
}
