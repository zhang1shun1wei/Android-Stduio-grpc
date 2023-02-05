package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.x509.Extension;
import com.mi.car.jsse.easysec.jcajce.PKIXCertStoreSelector;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedBuilderParameters;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedParameters;
import com.mi.car.jsse.easysec.jce.exception.ExtCertPathBuilderException;
import com.mi.car.jsse.easysec.util.Selector;
import com.mi.car.jsse.easysec.util.Store;
import com.mi.car.jsse.easysec.util.StoreException;
import com.mi.car.jsse.easysec.x509.ExtendedPKIXBuilderParameters;
import com.mi.car.jsse.easysec.x509.ExtendedPKIXParameters;
import com.mi.car.jsse.easysec.x509.X509AttributeCertStoreSelector;
import com.mi.car.jsse.easysec.x509.X509AttributeCertificate;
import com.mi.car.jsse.easysec.x509.X509CertStoreSelector;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Principal;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public class PKIXAttrCertPathBuilderSpi extends CertPathBuilderSpi {
    private Exception certPathException;

    public PKIXAttrCertPathBuilderSpi() {
    }

    public CertPathBuilderResult engineBuild(CertPathParameters params) throws CertPathBuilderException, InvalidAlgorithmParameterException {
        if (!(params instanceof PKIXBuilderParameters) && !(params instanceof ExtendedPKIXBuilderParameters) && !(params instanceof PKIXExtendedBuilderParameters)) {
            throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + PKIXBuilderParameters.class.getName() + " or " + PKIXExtendedBuilderParameters.class.getName() + ".");
        } else {
            List targetStores = new ArrayList();
            PKIXExtendedBuilderParameters paramsPKIX;
            if (params instanceof PKIXBuilderParameters) {
                PKIXExtendedBuilderParameters.Builder paramsPKIXBldr = new PKIXExtendedBuilderParameters.Builder((PKIXBuilderParameters)params);
                if (params instanceof ExtendedPKIXParameters) {
                    ExtendedPKIXBuilderParameters extPKIX = (ExtendedPKIXBuilderParameters)params;
                    paramsPKIXBldr.addExcludedCerts(extPKIX.getExcludedCerts());
                    paramsPKIXBldr.setMaxPathLength(extPKIX.getMaxPathLength());
                    targetStores = extPKIX.getStores();
                }

                paramsPKIX = paramsPKIXBldr.build();
            } else {
                paramsPKIX = (PKIXExtendedBuilderParameters)params;
            }

            List certPathList = new ArrayList();
            PKIXExtendedParameters baseParams = paramsPKIX.getBaseParameters();
            Selector certSelect = baseParams.getTargetConstraints();
            if (!(certSelect instanceof X509AttributeCertStoreSelector)) {
                throw new CertPathBuilderException("TargetConstraints must be an instance of " + X509AttributeCertStoreSelector.class.getName() + " for " + this.getClass().getName() + " class.");
            } else {
                Collection targets;
                try {
                    targets = findCertificates((X509AttributeCertStoreSelector)certSelect, (List)targetStores);
                } catch (AnnotatedException var16) {
                    throw new ExtCertPathBuilderException("Error finding target attribute certificate.", var16);
                }

                if (targets.isEmpty()) {
                    throw new CertPathBuilderException("No attribute certificate found matching targetConstraints.");
                } else {
                    CertPathBuilderResult result = null;
                    Iterator targetIter = targets.iterator();

                    while(targetIter.hasNext() && result == null) {
                        X509AttributeCertificate cert = (X509AttributeCertificate)targetIter.next();
                        X509CertStoreSelector selector = new X509CertStoreSelector();
                        Principal[] principals = cert.getIssuer().getPrincipals();
                        LinkedHashSet issuers = new LinkedHashSet();

                        for(int i = 0; i < principals.length; ++i) {
                            try {
                                if (principals[i] instanceof X500Principal) {
                                    selector.setSubject(((X500Principal)principals[i]).getEncoded());
                                }

                                PKIXCertStoreSelector certStoreSelector = (new com.mi.car.jsse.easysec.jcajce.PKIXCertStoreSelector.Builder(selector)).build();
                                CertPathValidatorUtilities.findCertificates(issuers, certStoreSelector, baseParams.getCertStores());
                                CertPathValidatorUtilities.findCertificates(issuers, certStoreSelector, baseParams.getCertificateStores());
                            } catch (AnnotatedException var17) {
                                throw new ExtCertPathBuilderException("Public key certificate for attribute certificate cannot be searched.", var17);
                            } catch (IOException var18) {
                                throw new ExtCertPathBuilderException("cannot encode X500Principal.", var18);
                            }
                        }

                        if (issuers.isEmpty()) {
                            throw new CertPathBuilderException("Public key certificate for attribute certificate cannot be found.");
                        }

                        for(Iterator it = issuers.iterator(); it.hasNext() && result == null; result = this.build(cert, (X509Certificate)it.next(), paramsPKIX, certPathList)) {
                        }
                    }

                    if (result == null && this.certPathException != null) {
                        throw new ExtCertPathBuilderException("Possible certificate chain could not be validated.", this.certPathException);
                    } else if (result == null && this.certPathException == null) {
                        throw new CertPathBuilderException("Unable to find certificate chain.");
                    } else {
                        return result;
                    }
                }
            }
        }
    }

    private CertPathBuilderResult build(X509AttributeCertificate attrCert, X509Certificate tbvCert, PKIXExtendedBuilderParameters pkixParams, List tbvPath) {
        if (tbvPath.contains(tbvCert)) {
            return null;
        } else if (pkixParams.getExcludedCerts().contains(tbvCert)) {
            return null;
        } else if (pkixParams.getMaxPathLength() != -1 && tbvPath.size() - 1 > pkixParams.getMaxPathLength()) {
            return null;
        } else {
            tbvPath.add(tbvCert);
            CertPathBuilderResult builderResult = null;

            CertificateFactory cFact;
            CertPathValidator validator;
            try {
                cFact = CertificateFactory.getInstance("X.509", "ES");
                validator = CertPathValidator.getInstance("RFC3281", "ES");
            } catch (Exception var17) {
                throw new RuntimeException("Exception creating support classes.");
            }

            try {
                PKIXExtendedParameters baseParams = pkixParams.getBaseParameters();
                if (CertPathValidatorUtilities.isIssuerTrustAnchor(tbvCert, baseParams.getTrustAnchors(), baseParams.getSigProvider())) {
                    CertPath certPath;
                    try {
                        certPath = cFact.generateCertPath(tbvPath);
                    } catch (Exception var14) {
                        throw new AnnotatedException("Certification path could not be constructed from certificate list.", var14);
                    }

                    PKIXCertPathValidatorResult result;
                    try {
                        result = (PKIXCertPathValidatorResult)validator.validate(certPath, pkixParams);
                    } catch (Exception var13) {
                        throw new AnnotatedException("Certification path could not be validated.", var13);
                    }

                    return new PKIXCertPathBuilderResult(certPath, result.getTrustAnchor(), result.getPolicyTree(), result.getPublicKey());
                }

                List stores = new ArrayList();
                stores.addAll(baseParams.getCertificateStores());

                try {
                    stores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromAltNames(tbvCert.getExtensionValue(Extension.issuerAlternativeName.getId()), baseParams.getNamedCertificateStoreMap()));
                } catch (CertificateParsingException var16) {
                    throw new AnnotatedException("No additional X.509 stores can be added from certificate locations.", var16);
                }

                HashSet issuers = new HashSet();

                try {
                    issuers.addAll(CertPathValidatorUtilities.findIssuerCerts(tbvCert, baseParams.getCertStores(), stores));
                } catch (AnnotatedException var15) {
                    throw new AnnotatedException("Cannot find issuer certificate for certificate in certification path.", var15);
                }

                if (issuers.isEmpty()) {
                    throw new AnnotatedException("No issuer certificate for certificate in certification path found.");
                }

                Iterator it = issuers.iterator();

                while(it.hasNext() && builderResult == null) {
                    X509Certificate issuer = (X509Certificate)it.next();
                    if (!issuer.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                        builderResult = this.build(attrCert, issuer, pkixParams, tbvPath);
                    }
                }
            } catch (AnnotatedException var18) {
                this.certPathException = new AnnotatedException("No valid certification path could be build.", var18);
            }

            if (builderResult == null) {
                tbvPath.remove(tbvCert);
            }

            return builderResult;
        }
    }

    protected static Collection findCertificates(X509AttributeCertStoreSelector certSelect, List certStores) throws AnnotatedException {
        Set certs = new HashSet();
        Iterator iter = certStores.iterator();

        while(iter.hasNext()) {
            Object obj = iter.next();
            if (obj instanceof Store) {
                Store certStore = (Store)obj;

                try {
                    certs.addAll(certStore.getMatches(certSelect));
                } catch (StoreException var7) {
                    throw new AnnotatedException("Problem while picking certificates from X.509 store.", var7);
                }
            }
        }

        return certs;
    }
}
