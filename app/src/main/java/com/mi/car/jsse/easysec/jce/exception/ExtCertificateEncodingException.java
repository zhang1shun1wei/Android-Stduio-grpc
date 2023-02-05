package com.mi.car.jsse.easysec.jce.exception;

import java.security.cert.CertificateEncodingException;

public class ExtCertificateEncodingException extends CertificateEncodingException implements ExtException {
    private Throwable cause;

    public ExtCertificateEncodingException(String message, Throwable cause2) {
        super(message);
        this.cause = cause2;
    }

    @Override // com.mi.car.jsse.easysec.jce.exception.ExtException
    public Throwable getCause() {
        return this.cause;
    }
}
