package com.mi.car.jsse.easysec.jce.provider;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;

class RecoverableCertPathValidatorException extends CertPathValidatorException {
    public RecoverableCertPathValidatorException(String msg, Throwable cause, CertPath certPath, int index) {
        super(msg, cause, certPath, index);
    }
}
