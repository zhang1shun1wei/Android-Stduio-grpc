package com.mi.car.jsse.easysec.jce;

import java.security.cert.CertStoreParameters;
import java.util.Collection;

public class MultiCertStoreParameters implements CertStoreParameters {
    private Collection certStores;
    private boolean searchAllStores;

    public MultiCertStoreParameters(Collection certStores2) {
        this(certStores2, true);
    }

    public MultiCertStoreParameters(Collection certStores2, boolean searchAllStores2) {
        this.certStores = certStores2;
        this.searchAllStores = searchAllStores2;
    }

    public Collection getCertStores() {
        return this.certStores;
    }

    public boolean getSearchAllStores() {
        return this.searchAllStores;
    }

    @Override // java.lang.Object
    public Object clone() {
        return this;
    }
}
