package com.mi.car.jsse.easysec.x509;

import com.mi.car.jsse.easysec.util.Selector;

import java.util.Collection;

public abstract class X509StoreSpi
{
    public abstract void engineInit(X509StoreParameters parameters);

    public abstract Collection engineGetMatches(Selector selector);
}
