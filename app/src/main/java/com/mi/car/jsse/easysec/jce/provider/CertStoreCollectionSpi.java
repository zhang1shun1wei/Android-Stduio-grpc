package com.mi.car.jsse.easysec.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class CertStoreCollectionSpi extends CertStoreSpi {
    private CollectionCertStoreParameters params;

    public CertStoreCollectionSpi(CertStoreParameters params2) throws InvalidAlgorithmParameterException {
        super(params2);
        if (!(params2 instanceof CollectionCertStoreParameters)) {
            throw new InvalidAlgorithmParameterException("com.mi.car.jsse.easysec.jce.provider.CertStoreCollectionSpi: parameter must be a CollectionCertStoreParameters object\n" + params2.toString());
        }
        this.params = (CollectionCertStoreParameters) params2;
    }

    @Override // java.security.cert.CertStoreSpi
    public Collection engineGetCertificates(CertSelector selector) throws CertStoreException {
        List col = new ArrayList();
        Iterator iter = this.params.getCollection().iterator();
        if (selector == null) {
            while (iter.hasNext()) {
                Object obj = iter.next();
                if (obj instanceof Certificate) {
                    col.add(obj);
                }
            }
        } else {
            while (iter.hasNext()) {
                Object obj2 = iter.next();
                if ((obj2 instanceof Certificate) && selector.match((Certificate) obj2)) {
                    col.add(obj2);
                }
            }
        }
        return col;
    }

    @Override // java.security.cert.CertStoreSpi
    public Collection engineGetCRLs(CRLSelector selector) throws CertStoreException {
        List col = new ArrayList();
        Iterator iter = this.params.getCollection().iterator();
        if (selector == null) {
            while (iter.hasNext()) {
                Object obj = iter.next();
                if (obj instanceof CRL) {
                    col.add(obj);
                }
            }
        } else {
            while (iter.hasNext()) {
                Object obj2 = iter.next();
                if ((obj2 instanceof CRL) && selector.match((CRL) obj2)) {
                    col.add(obj2);
                }
            }
        }
        return col;
    }
}
