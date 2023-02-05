package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.x509.CRLDistPoint;
import com.mi.car.jsse.easysec.asn1.x509.DistributionPoint;
import com.mi.car.jsse.easysec.asn1.x509.DistributionPointName;
import com.mi.car.jsse.easysec.asn1.x509.Extension;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.asn1.x509.GeneralNames;
import com.mi.car.jsse.easysec.asn1.x509.TargetInformation;
import com.mi.car.jsse.easysec.asn1.x509.X509Extensions;
import com.mi.car.jsse.easysec.jcajce.PKIXCRLStore;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationCheckerParameters;
import com.mi.car.jsse.easysec.jcajce.PKIXCertStoreSelector;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedBuilderParameters;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedParameters;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jce.exception.ExtCertPathValidatorException;
import com.mi.car.jsse.easysec.x509.PKIXAttrCertChecker;
import com.mi.car.jsse.easysec.x509.X509AttributeCertificate;
import com.mi.car.jsse.easysec.x509.X509CertStoreSelector;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

class RFC3281CertPathUtilities {
    private static final String AUTHORITY_INFO_ACCESS = Extension.authorityInfoAccess.getId();
    private static final String CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();
    private static final String NO_REV_AVAIL = Extension.noRevAvail.getId();
    private static final String TARGET_INFORMATION = Extension.targetInformation.getId();

    RFC3281CertPathUtilities() {
    }

    protected static void processAttrCert7(X509AttributeCertificate attrCert, CertPath certPath, CertPath holderCertPath, PKIXExtendedParameters pkixParams, Set attrCertCheckers) throws CertPathValidatorException {
        Set set = attrCert.getCriticalExtensionOIDs();
        if (set.contains(TARGET_INFORMATION)) {
            try {
                TargetInformation.getInstance(CertPathValidatorUtilities.getExtensionValue(attrCert, TARGET_INFORMATION));
            } catch (AnnotatedException e) {
                throw new ExtCertPathValidatorException("Target information extension could not be read.", e);
            } catch (IllegalArgumentException e2) {
                throw new ExtCertPathValidatorException("Target information extension could not be read.", e2);
            }
        }
        set.remove(TARGET_INFORMATION);
        Iterator it = attrCertCheckers.iterator();
        while (it.hasNext()) {
            ((PKIXAttrCertChecker) it.next()).check(attrCert, certPath, holderCertPath, set);
        }
        if (!set.isEmpty()) {
            throw new CertPathValidatorException("Attribute certificate contains unsupported critical extensions: " + set);
        }
    }

    protected static void checkCRLs(X509AttributeCertificate attrCert, PKIXExtendedParameters paramsPKIX, Date currentDate, Date validityDate, X509Certificate issuerCert, List certPathCerts, JcaJceHelper helper) throws CertPathValidatorException {
        if (!paramsPKIX.isRevocationEnabled()) {
            return;
        }
        if (attrCert.getExtensionValue(NO_REV_AVAIL) == null) {
            try {
                CRLDistPoint crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(attrCert, CRL_DISTRIBUTION_POINTS));
                List crlStores = new ArrayList();
                try {
                    crlStores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromCRLDistributionPoint(crldp, paramsPKIX.getNamedCRLStoreMap(), validityDate, helper));
                    PKIXExtendedParameters.Builder bldr = new PKIXExtendedParameters.Builder(paramsPKIX);
                    Iterator it = crlStores.iterator();
                    while (it.hasNext()) {
                        bldr.addCRLStore((PKIXCRLStore) crlStores);
                    }
                    PKIXExtendedParameters paramsPKIX2 = bldr.build();
                    CertStatus certStatus = new CertStatus();
                    ReasonsMask reasonsMask = new ReasonsMask();
                    AnnotatedException lastException = null;
                    boolean validCrlFound = false;
                    if (crldp != null) {
                        try {
                            DistributionPoint[] dps = crldp.getDistributionPoints();
                            for (int i = 0; i < dps.length && certStatus.getCertStatus() == 11 && !reasonsMask.isAllReasons(); i++) {
                                try {
                                    checkCRL(dps[i], attrCert, (PKIXExtendedParameters) paramsPKIX2.clone(), currentDate, validityDate, issuerCert, certStatus, reasonsMask, certPathCerts, helper);
                                    validCrlFound = true;
                                } catch (AnnotatedException e) {
                                    lastException = new AnnotatedException("No valid CRL for distribution point found.", e);
                                }
                            }
                        } catch (Exception e2) {
                            throw new ExtCertPathValidatorException("Distribution points could not be read.", e2);
                        }
                    }
                    if (certStatus.getCertStatus() == 11 && !reasonsMask.isAllReasons()) {
                        try {
                            try {
                                checkCRL(new DistributionPoint(new DistributionPointName(0, new GeneralNames(new GeneralName(4, PrincipalUtils.getEncodedIssuerPrincipal(attrCert)))), null, null), attrCert, (PKIXExtendedParameters) paramsPKIX2.clone(), currentDate, validityDate, issuerCert, certStatus, reasonsMask, certPathCerts, helper);
                                validCrlFound = true;
                            } catch (AnnotatedException e3) {
                                lastException = new AnnotatedException("No valid CRL for distribution point found.", e3);
                            }
                        } catch (Exception e4) {
                            throw new AnnotatedException("Issuer from certificate for CRL could not be reencoded.", e4);
                        }
                    }
                    if (!validCrlFound) {
                        throw new ExtCertPathValidatorException("No valid CRL found.", lastException);
                    } else if (certStatus.getCertStatus() != 11) {
                        throw new CertPathValidatorException(("Attribute certificate revocation after " + certStatus.getRevocationDate()) + ", reason: " + RFC3280CertPathUtilities.crlReasons[certStatus.getCertStatus()]);
                    } else {
                        if (!reasonsMask.isAllReasons() && certStatus.getCertStatus() == 11) {
                            certStatus.setCertStatus(12);
                        }
                        if (certStatus.getCertStatus() == 12) {
                            throw new CertPathValidatorException("Attribute certificate status could not be determined.");
                        }
                    }
                } catch (AnnotatedException e5) {
                    throw new CertPathValidatorException("No additional CRL locations could be decoded from CRL distribution point extension.", e5);
                }
            } catch (AnnotatedException e6) {
                throw new CertPathValidatorException("CRL distribution point extension could not be read.", e6);
            }
        } else if (attrCert.getExtensionValue(CRL_DISTRIBUTION_POINTS) != null || attrCert.getExtensionValue(AUTHORITY_INFO_ACCESS) != null) {
            throw new CertPathValidatorException("No rev avail extension is set, but also an AC revocation pointer.");
        }
    }

    protected static void additionalChecks(X509AttributeCertificate attrCert, Set prohibitedACAttributes, Set necessaryACAttributes) throws CertPathValidatorException {
        Iterator it = prohibitedACAttributes.iterator();
        while (it.hasNext()) {
            String oid = (String) it.next();
            if (attrCert.getAttributes(oid) != null) {
                throw new CertPathValidatorException("Attribute certificate contains prohibited attribute: " + oid + ".");
            }
        }
        Iterator it2 = necessaryACAttributes.iterator();
        while (it2.hasNext()) {
            String oid2 = (String) it2.next();
            if (attrCert.getAttributes(oid2) == null) {
                throw new CertPathValidatorException("Attribute certificate does not contain necessary attribute: " + oid2 + ".");
            }
        }
    }

    protected static void processAttrCert5(X509AttributeCertificate attrCert, Date validityDate) throws CertPathValidatorException {
        try {
            attrCert.checkValidity(validityDate);
        } catch (CertificateExpiredException e) {
            throw new ExtCertPathValidatorException("Attribute certificate is not valid.", e);
        } catch (CertificateNotYetValidException e2) {
            throw new ExtCertPathValidatorException("Attribute certificate is not valid.", e2);
        }
    }

    protected static void processAttrCert4(X509Certificate acIssuerCert, Set trustedACIssuers) throws CertPathValidatorException {
        boolean trusted = false;
        Iterator it = trustedACIssuers.iterator();
        while (it.hasNext()) {
            TrustAnchor anchor = (TrustAnchor) it.next();
            if (acIssuerCert.getSubjectX500Principal().getName("RFC2253").equals(anchor.getCAName()) || acIssuerCert.equals(anchor.getTrustedCert())) {
                trusted = true;
            }
        }
        if (!trusted) {
            throw new CertPathValidatorException("Attribute certificate issuer is not directly trusted.");
        }
    }

    protected static void processAttrCert3(X509Certificate acIssuerCert, PKIXExtendedParameters pkixParams) throws CertPathValidatorException {
        boolean[] keyUsage = acIssuerCert.getKeyUsage();
        if (keyUsage != null && ((keyUsage.length <= 0 || !keyUsage[0]) && (keyUsage.length <= 1 || !keyUsage[1]))) {
            throw new CertPathValidatorException("Attribute certificate issuer public key cannot be used to validate digital signatures.");
        } else if (acIssuerCert.getBasicConstraints() != -1) {
            throw new CertPathValidatorException("Attribute certificate issuer is also a public key certificate issuer.");
        }
    }

    protected static CertPathValidatorResult processAttrCert2(CertPath certPath, PKIXExtendedParameters pkixParams) throws CertPathValidatorException {
        try {
            try {
                return CertPathValidator.getInstance("PKIX", EasysecProvider.PROVIDER_NAME).validate(certPath, pkixParams);
            } catch (CertPathValidatorException e) {
                throw new ExtCertPathValidatorException("Certification path for issuer certificate of attribute certificate could not be validated.", e);
            } catch (InvalidAlgorithmParameterException e2) {
                throw new RuntimeException(e2.getMessage());
            }
        } catch (NoSuchProviderException e3) {
            throw new ExtCertPathValidatorException("Support class could not be created.", e3);
        } catch (NoSuchAlgorithmException e4) {
            throw new ExtCertPathValidatorException("Support class could not be created.", e4);
        }
    }

    protected static CertPath processAttrCert1(X509AttributeCertificate attrCert, PKIXExtendedParameters pkixParams) throws CertPathValidatorException {
        CertPathBuilderResult result = null;
        LinkedHashSet holderPKCs = new LinkedHashSet();
        if (attrCert.getHolder().getIssuer() != null) {
            X509CertSelector selector = new X509CertSelector();
            selector.setSerialNumber(attrCert.getHolder().getSerialNumber());
            Principal[] principals = attrCert.getHolder().getIssuer();
            for (int i = 0; i < principals.length; i++) {
                try {
                    if (principals[i] instanceof X500Principal) {
                        selector.setIssuer(((X500Principal) principals[i]).getEncoded());
                    }
                    CertPathValidatorUtilities.findCertificates(holderPKCs, new PKIXCertStoreSelector.Builder(selector).build(), pkixParams.getCertStores());
                } catch (AnnotatedException e) {
                    throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", e);
                } catch (IOException e2) {
                    throw new ExtCertPathValidatorException("Unable to encode X500 principal.", e2);
                }
            }
            if (holderPKCs.isEmpty()) {
                throw new CertPathValidatorException("Public key certificate specified in base certificate ID for attribute certificate cannot be found.");
            }
        }
        if (attrCert.getHolder().getEntityNames() != null) {
            X509CertStoreSelector selector2 = new X509CertStoreSelector();
            Principal[] principals2 = attrCert.getHolder().getEntityNames();
            for (int i2 = 0; i2 < principals2.length; i2++) {
                try {
                    if (principals2[i2] instanceof X500Principal) {
                        selector2.setIssuer(((X500Principal) principals2[i2]).getEncoded());
                    }
                    CertPathValidatorUtilities.findCertificates(holderPKCs, new PKIXCertStoreSelector.Builder(selector2).build(), pkixParams.getCertStores());
                } catch (AnnotatedException e3) {
                    throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", e3);
                } catch (IOException e4) {
                    throw new ExtCertPathValidatorException("Unable to encode X500 principal.", e4);
                }
            }
            if (holderPKCs.isEmpty()) {
                throw new CertPathValidatorException("Public key certificate specified in entity name for attribute certificate cannot be found.");
            }
        }
        PKIXExtendedParameters.Builder paramsBldr = new PKIXExtendedParameters.Builder(pkixParams);
        CertPathValidatorException lastException = null;
        Iterator it = holderPKCs.iterator();
        while (it.hasNext()) {
            X509CertStoreSelector selector3 = new X509CertStoreSelector();
            selector3.setCertificate((X509Certificate) it.next());
            paramsBldr.setTargetConstraints(new PKIXCertStoreSelector.Builder(selector3).build());
            try {
                try {
                    result = CertPathBuilder.getInstance("PKIX", EasysecProvider.PROVIDER_NAME).build(new PKIXExtendedBuilderParameters.Builder(paramsBldr.build()).build());
                } catch (CertPathBuilderException e5) {
                    lastException = new ExtCertPathValidatorException("Certification path for public key certificate of attribute certificate could not be build.", e5);
                } catch (InvalidAlgorithmParameterException e6) {
                    throw new RuntimeException(e6.getMessage());
                }
            } catch (NoSuchProviderException e7) {
                throw new ExtCertPathValidatorException("Support class could not be created.", e7);
            } catch (NoSuchAlgorithmException e8) {
                throw new ExtCertPathValidatorException("Support class could not be created.", e8);
            }
        }
        if (lastException == null) {
            return result.getCertPath();
        }
        throw lastException;
    }

    private static void checkCRL(DistributionPoint dp, X509AttributeCertificate attrCert, PKIXExtendedParameters paramsPKIX, Date currentDate, Date validityDate, X509Certificate issuerCert, CertStatus certStatus, ReasonsMask reasonMask, List certPathCerts, JcaJceHelper helper) throws AnnotatedException, RecoverableCertPathValidatorException {
        if (attrCert.getExtensionValue(X509Extensions.NoRevAvail.getId()) == null) {
            if (validityDate.getTime() > currentDate.getTime()) {
                throw new AnnotatedException("Validation time is in future.");
            }
            boolean validCrlFound = false;
            AnnotatedException lastException = null;
            Iterator crl_iter = CertPathValidatorUtilities.getCompleteCRLs(new PKIXCertRevocationCheckerParameters(paramsPKIX, validityDate, null, -1, issuerCert, null), dp, attrCert, paramsPKIX, validityDate).iterator();
            while (crl_iter.hasNext() && certStatus.getCertStatus() == 11 && !reasonMask.isAllReasons()) {
                try {
                    X509CRL crl = (X509CRL) crl_iter.next();
                    ReasonsMask interimReasonsMask = RFC3280CertPathUtilities.processCRLD(crl, dp);
                    if (interimReasonsMask.hasNewReasons(reasonMask)) {
                        PublicKey key = RFC3280CertPathUtilities.processCRLG(crl, RFC3280CertPathUtilities.processCRLF(crl, attrCert, null, null, paramsPKIX, certPathCerts, helper));
                        X509CRL deltaCRL = null;
                        if (paramsPKIX.isUseDeltasEnabled()) {
                            deltaCRL = RFC3280CertPathUtilities.processCRLH(CertPathValidatorUtilities.getDeltaCRLs(currentDate, crl, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores(), helper), key);
                        }
                        if (paramsPKIX.getValidityModel() == 1 || attrCert.getNotAfter().getTime() >= crl.getThisUpdate().getTime()) {
                            RFC3280CertPathUtilities.processCRLB1(dp, attrCert, crl);
                            RFC3280CertPathUtilities.processCRLB2(dp, attrCert, crl);
                            RFC3280CertPathUtilities.processCRLC(deltaCRL, crl, paramsPKIX);
                            RFC3280CertPathUtilities.processCRLI(validityDate, deltaCRL, attrCert, certStatus, paramsPKIX);
                            RFC3280CertPathUtilities.processCRLJ(validityDate, crl, attrCert, certStatus);
                            if (certStatus.getCertStatus() == 8) {
                                certStatus.setCertStatus(11);
                            }
                            reasonMask.addReasons(interimReasonsMask);
                            validCrlFound = true;
                        } else {
                            throw new AnnotatedException("No valid CRL for current time found.");
                        }
                    } else {
                        continue;
                    }
                } catch (AnnotatedException e) {
                    lastException = e;
                }
            }
            if (!validCrlFound) {
                throw lastException;
            }
        }
    }
}
