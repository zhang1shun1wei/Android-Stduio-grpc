package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.isara.IsaraObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.internal.asn1.bsi.BSIObjectIdentifiers;
import com.mi.car.jsse.easysec.internal.asn1.eac.EACObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationCheckerParameters;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* access modifiers changed from: package-private */
public class ProvRevocationChecker extends PKIXRevocationChecker implements PKIXCertRevocationChecker {
    private static final int DEFAULT_OCSP_MAX_RESPONSE_SIZE = 32768;
    private static final int DEFAULT_OCSP_TIMEOUT = 15000;
    private static final Map oids = new HashMap();
    private final ProvCrlRevocationChecker crlChecker;
    private final JcaJceHelper helper;
    private final ProvOcspRevocationChecker ocspChecker;
    private PKIXCertRevocationCheckerParameters parameters;

    static {
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        oids.put(IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
        oids.put(IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        oids.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        oids.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
    }

    public ProvRevocationChecker(JcaJceHelper helper2) {
        this.helper = helper2;
        this.crlChecker = new ProvCrlRevocationChecker(helper2);
        this.ocspChecker = new ProvOcspRevocationChecker(this, helper2);
    }

    @Override // com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker
    public void setParameter(String name, Object value) {
    }

    @Override // com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationChecker
    public void initialize(PKIXCertRevocationCheckerParameters parameters2) {
        this.parameters = parameters2;
        this.crlChecker.initialize(parameters2);
        this.ocspChecker.initialize(parameters2);
    }

    @Override // java.security.cert.PKIXRevocationChecker
    public List<CertPathValidatorException> getSoftFailExceptions() {
        return this.ocspChecker.getSoftFailExceptions();
    }

    @Override // java.security.cert.PKIXCertPathChecker, java.security.cert.CertPathChecker
    public void init(boolean forForward) throws CertPathValidatorException {
        this.parameters = null;
        this.crlChecker.init(forForward);
        this.ocspChecker.init(forForward);
    }

    public boolean isForwardCheckingSupported() {
        return false;
    }

    @Override // java.security.cert.PKIXCertPathChecker
    public Set<String> getSupportedExtensions() {
        return null;
    }

    @Override // java.security.cert.PKIXCertPathChecker
    public void check(Certificate certificate, Collection<String> collection) throws CertPathValidatorException {
        X509Certificate cert = (X509Certificate) certificate;
        if (hasOption(Option.ONLY_END_ENTITY) && cert.getBasicConstraints() != -1) {
            return;
        }
        if (hasOption(Option.PREFER_CRLS)) {
            try {
                this.crlChecker.check(certificate);
            } catch (RecoverableCertPathValidatorException e) {
                if (!hasOption(Option.NO_FALLBACK)) {
                    this.ocspChecker.check(certificate);
                    return;
                }
                throw e;
            }
        } else {
            try {
                this.ocspChecker.check(certificate);
            } catch (RecoverableCertPathValidatorException e2) {
                if (!hasOption(Option.NO_FALLBACK)) {
                    this.crlChecker.check(certificate);
                    return;
                }
                throw e2;
            }
        }
    }

    private boolean hasOption(Option option) {
        return getOptions().contains(option);
    }
}
