package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.Extension;
import com.mi.car.jsse.easysec.asn1.x509.TBSCertificate;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedBuilderParameters;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedParameters;
import com.mi.car.jsse.easysec.jcajce.interfaces.BCX509Certificate;
import com.mi.car.jsse.easysec.jcajce.util.BCJcaJceHelper;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jce.exception.ExtCertPathValidatorException;
import com.mi.car.jsse.easysec.x509.ExtendedPKIXParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PKIXCertPathValidatorSpi extends CertPathValidatorSpi {
    private final JcaJceHelper helper;
    private final boolean isForCRLCheck;

    public PKIXCertPathValidatorSpi() {
        this(false);
    }

    public PKIXCertPathValidatorSpi(boolean isForCRLCheck2) {
        this.helper = new BCJcaJceHelper();
        this.isForCRLCheck = isForCRLCheck2;
    }

    @Override // java.security.cert.CertPathValidatorSpi
    public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        PKIXExtendedParameters paramsPKIX;
        int explicitPolicy;
        int inhibitAnyPolicy;
        int policyMapping;
        X500Name workingIssuerName;
        PublicKey workingPublicKey;
        ProvCrlRevocationChecker revocationChecker;
        Set criticalExtensions;
        Set criticalExtensions2;
        if (params instanceof PKIXParameters) {
            PKIXExtendedParameters.Builder paramsPKIXBldr = new PKIXExtendedParameters.Builder((PKIXParameters) params);
            if (params instanceof ExtendedPKIXParameters) {
                ExtendedPKIXParameters extPKIX = (ExtendedPKIXParameters) params;
                paramsPKIXBldr.setUseDeltasEnabled(extPKIX.isUseDeltasEnabled());
                paramsPKIXBldr.setValidityModel(extPKIX.getValidityModel());
            }
            paramsPKIX = paramsPKIXBldr.build();
        } else if (params instanceof PKIXExtendedBuilderParameters) {
            paramsPKIX = ((PKIXExtendedBuilderParameters) params).getBaseParameters();
        } else if (params instanceof PKIXExtendedParameters) {
            paramsPKIX = (PKIXExtendedParameters) params;
        } else {
            throw new InvalidAlgorithmParameterException("Parameters must be a " + PKIXParameters.class.getName() + " instance.");
        }
        if (paramsPKIX.getTrustAnchors() == null) {
            throw new InvalidAlgorithmParameterException("trustAnchors is null, this is not allowed for certification path validation.");
        }
        List certs = certPath.getCertificates();
        int n = certs.size();
        if (certs.isEmpty()) {
            throw new CertPathValidatorException("Certification path is empty.", null, certPath, -1);
        }
        Date validityDate = CertPathValidatorUtilities.getValidityDate(paramsPKIX, new Date());
        Set userInitialPolicySet = paramsPKIX.getInitialPolicies();
        try {
            TrustAnchor trust = CertPathValidatorUtilities.findTrustAnchor((X509Certificate) certs.get(certs.size() - 1), paramsPKIX.getTrustAnchors(), paramsPKIX.getSigProvider());
            if (trust == null) {
                throw new CertPathValidatorException("Trust anchor for certification path not found.", null, certPath, -1);
            }
            checkCertificate(trust.getTrustedCert());
            PKIXExtendedParameters paramsPKIX2 = new PKIXExtendedParameters.Builder(paramsPKIX).setTrustAnchor(trust).build();
            List[] policyNodes = new ArrayList[(n + 1)];
            for (int j = 0; j < policyNodes.length; j++) {
                policyNodes[j] = new ArrayList();
            }
            Set policySet = new HashSet();
            policySet.add(RFC3280CertPathUtilities.ANY_POLICY);
            PKIXPolicyNode validPolicyTree = new PKIXPolicyNode(new ArrayList(), 0, policySet, null, new HashSet(), RFC3280CertPathUtilities.ANY_POLICY, false);
            policyNodes[0].add(validPolicyTree);
            PKIXNameConstraintValidator nameConstraintValidator = new PKIXNameConstraintValidator();
            Set acceptablePolicies = new HashSet();
            if (paramsPKIX2.isExplicitPolicyRequired()) {
                explicitPolicy = 0;
            } else {
                explicitPolicy = n + 1;
            }
            if (paramsPKIX2.isAnyPolicyInhibited()) {
                inhibitAnyPolicy = 0;
            } else {
                inhibitAnyPolicy = n + 1;
            }
            if (paramsPKIX2.isPolicyMappingInhibited()) {
                policyMapping = 0;
            } else {
                policyMapping = n + 1;
            }
            X509Certificate sign = trust.getTrustedCert();
            if (sign != null) {
                try {
                    workingIssuerName = PrincipalUtils.getSubjectPrincipal(sign);
                    workingPublicKey = sign.getPublicKey();
                } catch (RuntimeException ex) {
                    throw new ExtCertPathValidatorException("Subject of trust anchor could not be (re)encoded.", ex, certPath, -1);
                }
            } else {
                workingIssuerName = PrincipalUtils.getCA(trust);
                workingPublicKey = trust.getCAPublicKey();
            }
            try {
                AlgorithmIdentifier workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
                workingAlgId.getAlgorithm();
                workingAlgId.getParameters();
                int maxPathLength = n;
                if (paramsPKIX2.getTargetConstraints() == null || paramsPKIX2.getTargetConstraints().match((Certificate) ((X509Certificate) certs.get(0)))) {
                    List<PKIXCertPathChecker> pathCheckers = paramsPKIX2.getCertPathCheckers();
                    for (PKIXCertPathChecker pKIXCertPathChecker : pathCheckers) {
                        pKIXCertPathChecker.init(false);
                    }
                    if (paramsPKIX2.isRevocationEnabled()) {
                        revocationChecker = new ProvCrlRevocationChecker(this.helper);
                    } else {
                        revocationChecker = null;
                    }
                    X509Certificate cert = null;
                    int index = certs.size() - 1;
                    while (index >= 0) {
                        int i = n - index;
                        cert = (X509Certificate) certs.get(index);
                        boolean verificationAlreadyPerformed = index == certs.size() + -1;
                        try {
                            checkCertificate(cert);
                            RFC3280CertPathUtilities.processCertA(certPath, paramsPKIX2, validityDate, revocationChecker, index, workingPublicKey, verificationAlreadyPerformed, workingIssuerName, sign);
                            RFC3280CertPathUtilities.processCertBC(certPath, index, nameConstraintValidator, this.isForCRLCheck);
                            validPolicyTree = RFC3280CertPathUtilities.processCertE(certPath, index, RFC3280CertPathUtilities.processCertD(certPath, index, acceptablePolicies, validPolicyTree, policyNodes, inhibitAnyPolicy, this.isForCRLCheck));
                            RFC3280CertPathUtilities.processCertF(certPath, index, validPolicyTree, explicitPolicy);
                            if (i != n) {
                                if (cert == null || cert.getVersion() != 1) {
                                    RFC3280CertPathUtilities.prepareNextCertA(certPath, index);
                                    validPolicyTree = RFC3280CertPathUtilities.prepareCertB(certPath, index, policyNodes, validPolicyTree, policyMapping);
                                    RFC3280CertPathUtilities.prepareNextCertG(certPath, index, nameConstraintValidator);
                                    int explicitPolicy2 = RFC3280CertPathUtilities.prepareNextCertH1(certPath, index, explicitPolicy);
                                    int policyMapping2 = RFC3280CertPathUtilities.prepareNextCertH2(certPath, index, policyMapping);
                                    int inhibitAnyPolicy2 = RFC3280CertPathUtilities.prepareNextCertH3(certPath, index, inhibitAnyPolicy);
                                    explicitPolicy = RFC3280CertPathUtilities.prepareNextCertI1(certPath, index, explicitPolicy2);
                                    policyMapping = RFC3280CertPathUtilities.prepareNextCertI2(certPath, index, policyMapping2);
                                    inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertJ(certPath, index, inhibitAnyPolicy2);
                                    RFC3280CertPathUtilities.prepareNextCertK(certPath, index);
                                    maxPathLength = RFC3280CertPathUtilities.prepareNextCertM(certPath, index, RFC3280CertPathUtilities.prepareNextCertL(certPath, index, maxPathLength));
                                    RFC3280CertPathUtilities.prepareNextCertN(certPath, index);
                                    Set criticalExtensions3 = cert.getCriticalExtensionOIDs();
                                    if (criticalExtensions3 != null) {
                                        Set criticalExtensions4 = new HashSet(criticalExtensions3);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.KEY_USAGE);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                                        criticalExtensions4.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                                        criticalExtensions2 = criticalExtensions4;
                                    } else {
                                        criticalExtensions2 = new HashSet();
                                    }
                                    RFC3280CertPathUtilities.prepareNextCertO(certPath, index, criticalExtensions2, pathCheckers);
                                    sign = cert;
                                    workingIssuerName = PrincipalUtils.getSubjectPrincipal(sign);
                                    try {
                                        workingPublicKey = CertPathValidatorUtilities.getNextWorkingKey(certPath.getCertificates(), index, this.helper);
                                        AlgorithmIdentifier workingAlgId2 = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
                                        workingAlgId2.getAlgorithm();
                                        workingAlgId2.getParameters();
                                    } catch (CertPathValidatorException e) {
                                        throw new CertPathValidatorException("Next working key could not be retrieved.", e, certPath, index);
                                    }
                                } else if (i != 1 || !cert.equals(trust.getTrustedCert())) {
                                    throw new CertPathValidatorException("Version 1 certificates can't be used as CA ones.", null, certPath, index);
                                }
                            }
                            index--;
                        } catch (AnnotatedException e2) {
                            throw new CertPathValidatorException(e2.getMessage(), e2.getUnderlyingException(), certPath, index);
                        }
                    }
                    int explicitPolicy3 = RFC3280CertPathUtilities.wrapupCertB(certPath, index + 1, RFC3280CertPathUtilities.wrapupCertA(explicitPolicy, cert));
                    Set criticalExtensions5 = cert.getCriticalExtensionOIDs();
                    if (criticalExtensions5 != null) {
                        Set criticalExtensions6 = new HashSet(criticalExtensions5);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.KEY_USAGE);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                        criticalExtensions6.remove(RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS);
                        criticalExtensions6.remove(Extension.extendedKeyUsage.getId());
                        criticalExtensions = criticalExtensions6;
                    } else {
                        criticalExtensions = new HashSet();
                    }
                    RFC3280CertPathUtilities.wrapupCertF(certPath, index + 1, pathCheckers, criticalExtensions);
                    PKIXPolicyNode intersection = RFC3280CertPathUtilities.wrapupCertG(certPath, paramsPKIX2, userInitialPolicySet, index + 1, policyNodes, validPolicyTree, acceptablePolicies);
                    if (explicitPolicy3 > 0 || intersection != null) {
                        return new PKIXCertPathValidatorResult(trust, intersection, cert.getPublicKey());
                    }
                    throw new CertPathValidatorException("Path processing failed on policy.", null, certPath, index);
                }
                throw new ExtCertPathValidatorException("Target certificate in certification path does not match targetConstraints.", null, certPath, 0);
            } catch (CertPathValidatorException e3) {
                throw new ExtCertPathValidatorException("Algorithm identifier of public key of trust anchor could not be read.", e3, certPath, -1);
            }
        } catch (AnnotatedException e4) {
            throw new CertPathValidatorException(e4.getMessage(), e4.getUnderlyingException(), certPath, certs.size() - 1);
        }
    }

    static void checkCertificate(X509Certificate cert) throws AnnotatedException {
        if (cert instanceof BCX509Certificate) {
            RuntimeException cause = null;
            try {
                if (((BCX509Certificate) cert).getTBSCertificateNative() != null) {
                    return;
                }
            } catch (RuntimeException e) {
                cause = e;
            }
            throw new AnnotatedException("unable to process TBSCertificate", cause);
        }
        try {
            TBSCertificate.getInstance(cert.getTBSCertificate());
        } catch (CertificateEncodingException e2) {
            throw new AnnotatedException("unable to process TBSCertificate", e2);
        } catch (IllegalArgumentException e3) {
            throw new AnnotatedException(e3.getMessage());
        }
    }
}
