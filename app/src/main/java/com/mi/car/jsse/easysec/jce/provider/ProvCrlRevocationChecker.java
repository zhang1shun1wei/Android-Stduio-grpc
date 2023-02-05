package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationCheckerParameters;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/* access modifiers changed from: package-private */
public class ProvCrlRevocationChecker implements PKIXCertRevocationChecker {
    private Date currentDate = null;
    private final JcaJceHelper helper;
    private PKIXCertRevocationCheckerParameters params;

    public ProvCrlRevocationChecker(JcaJceHelper helper2) {
        this.helper = helper2;
    }

    @Override // com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker
    public void setParameter(String name, Object value) {
    }

    @Override // com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker
    public void initialize(PKIXCertRevocationCheckerParameters params2) {
        this.params = params2;
        this.currentDate = new Date();
    }

    public void init(boolean forForward) throws CertPathValidatorException {
        if (forForward) {
            throw new CertPathValidatorException("forward checking not supported");
        }
        this.params = null;
        this.currentDate = new Date();
    }

    @Override // com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker
    public void check(Certificate certificate) throws CertPathValidatorException {
        try {
            RFC3280CertPathUtilities.checkCRLs(this.params, this.params.getParamsPKIX(), this.currentDate, this.params.getValidDate(), (X509Certificate) certificate, this.params.getSigningCert(), this.params.getWorkingPublicKey(), this.params.getCertPath().getCertificates(), this.helper);
        } catch (AnnotatedException e) {
            Throwable cause = e;
            if (e.getCause() != null) {
                cause = e.getCause();
            }
            throw new CertPathValidatorException(e.getMessage(), cause, this.params.getCertPath(), this.params.getIndex());
        }
    }
}
