package com.mi.car.jsse.easysec.util;

public class StoreException extends RuntimeException {
    private Throwable _e;

    public StoreException(String msg, Throwable cause) {
        super(msg);
        this._e = cause;
    }

    public Throwable getCause() {
        return this._e;
    }
}
