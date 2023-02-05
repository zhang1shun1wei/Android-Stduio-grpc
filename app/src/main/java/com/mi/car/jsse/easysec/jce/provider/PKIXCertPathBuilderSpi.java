package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.x509.Extension;
import com.mi.car.jsse.easysec.jcajce.PKIXCertStore;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedBuilderParameters;
import com.mi.car.jsse.easysec.jcajce.PKIXExtendedParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.x509.CertificateFactory;
import com.mi.car.jsse.easysec.x509.ExtendedPKIXBuilderParameters;
import com.mi.car.jsse.easysec.x509.ExtendedPKIXParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

public class PKIXCertPathBuilderSpi extends CertPathBuilderSpi {
    private final boolean isForCRLCheck;
    private Exception certPathException;

    public PKIXCertPathBuilderSpi() {
        this(false);
    }

    PKIXCertPathBuilderSpi(boolean isForCRLCheck) {
        this.isForCRLCheck = isForCRLCheck;
    }

    public CertPathBuilderResult engineBuild(CertPathParameters params) throws CertPathBuilderException, InvalidAlgorithmParameterException {
        PKIXExtendedBuilderParameters paramsPKIX;
        if (params instanceof PKIXBuilderParameters) {
            PKIXExtendedParameters.Builder paramsPKIXBldr = new PKIXExtendedParameters.Builder((PKIXBuilderParameters)params);
            PKIXExtendedBuilderParameters.Builder paramsBldrPKIXBldr;
            if (!(params instanceof ExtendedPKIXParameters)) {
                paramsBldrPKIXBldr = new com.mi.car.jsse.easysec.jcajce.PKIXExtendedBuilderParameters.Builder((PKIXBuilderParameters)params);
            } else {
                ExtendedPKIXBuilderParameters extPKIX = (ExtendedPKIXBuilderParameters)params;
                Iterator it = extPKIX.getAdditionalStores().iterator();

                while(it.hasNext()) {
                    paramsPKIXBldr.addCertificateStore((PKIXCertStore)it.next());
                }

                paramsBldrPKIXBldr = new com.mi.car.jsse.easysec.jcajce.PKIXExtendedBuilderParameters.Builder(paramsPKIXBldr.build());
                paramsBldrPKIXBldr.addExcludedCerts(extPKIX.getExcludedCerts());
                paramsBldrPKIXBldr.setMaxPathLength(extPKIX.getMaxPathLength());
            }

            paramsPKIX = paramsBldrPKIXBldr.build();
        } else {
            if (!(params instanceof PKIXExtendedBuilderParameters)) {
                throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + PKIXBuilderParameters.class.getName() + " or " + PKIXExtendedBuilderParameters.class.getName() + ".");
            }

            paramsPKIX = (PKIXExtendedBuilderParameters)params;
        }

        List certPathList = new ArrayList();
        Collection targets = CertPathValidatorUtilities.findTargets(paramsPKIX);
        CertPathBuilderResult result = null;

        X509Certificate cert;
        for(Iterator targetIter = targets.iterator(); targetIter.hasNext() && result == null; result = this.build(cert, paramsPKIX, certPathList)) {
            cert = (X509Certificate)targetIter.next();
        }

        if (result == null && this.certPathException != null) {
            if (this.certPathException instanceof AnnotatedException) {
                throw new CertPathBuilderException(this.certPathException.getMessage(), this.certPathException.getCause());
            } else {
                throw new CertPathBuilderException("Possible certificate chain could not be validated.", this.certPathException);
            }
        } else if (result == null && this.certPathException == null) {
            throw new CertPathBuilderException("Unable to find certificate chain.");
        } else {
            return result;
        }
    }

    protected CertPathBuilderResult build(X509Certificate tbvCert, PKIXExtendedBuilderParameters pkixParams, List tbvPath) {
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
            PKIXCertPathValidatorSpi validator;
            try {
                cFact = new CertificateFactory();
                validator = new PKIXCertPathValidatorSpi(this.isForCRLCheck);
            } catch (Exception var15) {
                throw new RuntimeException("Exception creating support classes.");
            }

            try {
                ArrayList stores;
                HashSet issuers;
                if (CertPathValidatorUtilities.isIssuerTrustAnchor(tbvCert, pkixParams.getBaseParameters().getTrustAnchors(), pkixParams.getBaseParameters().getSigProvider())) {
                    stores = null;
                    issuers = null;

                    CertPath certPath;
                    try {
                        certPath = cFact.engineGenerateCertPath(tbvPath);
                    } catch (Exception var12) {
                        throw new AnnotatedException("Certification path could not be constructed from certificate list.", var12);
                    }

                    PKIXCertPathValidatorResult result;
                    try {
                        result = (PKIXCertPathValidatorResult)validator.engineValidate(certPath, pkixParams);
                    } catch (Exception var11) {
                        throw new AnnotatedException("Certification path could not be validated.", var11);
                    }

                    return new PKIXCertPathBuilderResult(certPath, result.getTrustAnchor(), result.getPolicyTree(), result.getPublicKey());
                }

                stores = new ArrayList();
                stores.addAll(pkixParams.getBaseParameters().getCertificateStores());

                try {
                    stores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromAltNames(tbvCert.getExtensionValue(Extension.issuerAlternativeName.getId()), pkixParams.getBaseParameters().getNamedCertificateStoreMap()));
                } catch (CertificateParsingException var14) {
                    throw new AnnotatedException("No additional X.509 stores can be added from certificate locations.", var14);
                }

                issuers = new HashSet();

                try {
                    issuers.addAll(CertPathValidatorUtilities.findIssuerCerts(tbvCert, pkixParams.getBaseParameters().getCertStores(), stores));
                } catch (AnnotatedException var13) {
                    throw new AnnotatedException("Cannot find issuer certificate for certificate in certification path.", var13);
                }

                if (issuers.isEmpty()) {
                    throw new AnnotatedException("No issuer certificate for certificate in certification path found.");
                }

                X509Certificate issuer;
                for(Iterator it = issuers.iterator(); it.hasNext() && builderResult == null; builderResult = this.build(issuer, pkixParams, tbvPath)) {
                    issuer = (X509Certificate)it.next();
                }
            } catch (AnnotatedException var16) {
                this.certPathException = var16;
            }

            if (builderResult == null) {
                tbvPath.remove(tbvCert);
            }

            return builderResult;
        }
    }
}
