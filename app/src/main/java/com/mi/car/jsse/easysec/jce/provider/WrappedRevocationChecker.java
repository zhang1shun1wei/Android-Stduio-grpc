package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationCheckerParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;

/* access modifiers changed from: package-private */
public class WrappedRevocationChecker implements PKIXCertRevocationChecker {
    private final PKIXCertPathChecker checker;

    public WrappedRevocationChecker(PKIXCertPathChecker checker2) {
        this.checker = checker2;
    }

    @Override // com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker
    public void setParameter(String name, Object value) {
    }

    @Override // com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker
    public void initialize(PKIXCertRevocationCheckerParameters params) throws CertPathValidatorException {
        this.checker.init(false);
    }

    @Override // com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker
    public void check(Certificate cert) throws CertPathValidatorException {
        this.checker.check(cert);
    }
}
