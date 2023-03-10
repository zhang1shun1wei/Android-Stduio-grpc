package com.mi.car.jsse.easysec.jce.exception;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;

public class ExtCertPathValidatorException extends CertPathValidatorException implements ExtException {
    private Throwable cause;

    public ExtCertPathValidatorException(String message) {
        super(message);
    }

    public ExtCertPathValidatorException(String message, Throwable cause2) {
        super(message);
        this.cause = cause2;
    }

    public ExtCertPathValidatorException(String msg, Throwable cause2, CertPath certPath, int index) {
        super(msg, cause2, certPath, index);
        this.cause = cause2;
    }

    @Override // com.mi.car.jsse.easysec.jce.exception.ExtException
    public Throwable getCause() {
        return this.cause;
    }
}
