package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.jce.MultiCertStoreParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class MultiCertStoreSpi extends CertStoreSpi {
    private MultiCertStoreParameters params;

    public MultiCertStoreSpi(CertStoreParameters params) throws InvalidAlgorithmParameterException {
        super(params);
        if (!(params instanceof MultiCertStoreParameters)) {
            throw new InvalidAlgorithmParameterException("com.mi.car.jsse.easysec.jce.provider.MultiCertStoreSpi: parameter must be a MultiCertStoreParameters object\n" + params.toString());
        } else {
            this.params = (MultiCertStoreParameters)params;
        }
    }

    public Collection engineGetCertificates(CertSelector certSelector) throws CertStoreException {
        boolean searchAllStores = this.params.getSearchAllStores();
        Iterator iter = this.params.getCertStores().iterator();
        Object allCerts = searchAllStores ? new ArrayList() : Collections.EMPTY_LIST;

        while(iter.hasNext()) {
            CertStore store = (CertStore)iter.next();
            Collection certs = store.getCertificates(certSelector);
            if (searchAllStores) {
                ((List)allCerts).addAll(certs);
            } else if (!certs.isEmpty()) {
                return certs;
            }
        }

        return (Collection)allCerts;
    }

    public Collection engineGetCRLs(CRLSelector crlSelector) throws CertStoreException {
        boolean searchAllStores = this.params.getSearchAllStores();
        Iterator iter = this.params.getCertStores().iterator();
        Object allCRLs = searchAllStores ? new ArrayList() : Collections.EMPTY_LIST;

        while(iter.hasNext()) {
            CertStore store = (CertStore)iter.next();
            Collection crls = store.getCRLs(crlSelector);
            if (searchAllStores) {
                ((List)allCRLs).addAll(crls);
            } else if (!crls.isEmpty()) {
                return crls;
            }
        }

        return (Collection)allCRLs;
    }
}
