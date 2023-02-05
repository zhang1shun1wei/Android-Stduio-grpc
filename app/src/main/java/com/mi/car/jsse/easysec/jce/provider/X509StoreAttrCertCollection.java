package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.util.CollectionStore;
import com.mi.car.jsse.easysec.util.Selector;
import com.mi.car.jsse.easysec.x509.X509CollectionStoreParameters;
import com.mi.car.jsse.easysec.x509.X509StoreParameters;
import com.mi.car.jsse.easysec.x509.X509StoreSpi;
import java.util.Collection;

public class X509StoreAttrCertCollection extends X509StoreSpi {
    private CollectionStore _store;

    @Override // com.mi.car.jsse.easysec.x509.X509StoreSpi
    public void engineInit(X509StoreParameters params) {
        if (!(params instanceof X509CollectionStoreParameters)) {
            throw new IllegalArgumentException(params.toString());
        }
        this._store = new CollectionStore(((X509CollectionStoreParameters) params).getCollection());
    }

    @Override // com.mi.car.jsse.easysec.x509.X509StoreSpi
    public Collection engineGetMatches(Selector selector) {
        return this._store.getMatches(selector);
    }
}
