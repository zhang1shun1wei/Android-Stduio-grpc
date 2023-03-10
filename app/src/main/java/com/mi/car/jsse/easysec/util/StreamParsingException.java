package com.mi.car.jsse.easysec.util;

public class StreamParsingException extends Exception {
    Throwable _e;

    public StreamParsingException(String message, Throwable e) {
        super(message);
        this._e = e;
    }

    public Throwable getCause() {
        return this._e;
    }
}
