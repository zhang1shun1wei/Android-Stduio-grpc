package com.mi.car.jsse.easysec.jce.provider;

import java.security.cert.CRLException;

/* access modifiers changed from: package-private */
public class ExtCRLException extends CRLException {
    Throwable cause;

    ExtCRLException(String message, Throwable cause2) {
        super(message);
        this.cause = cause2;
    }

    public Throwable getCause() {
        return this.cause;
    }
}
