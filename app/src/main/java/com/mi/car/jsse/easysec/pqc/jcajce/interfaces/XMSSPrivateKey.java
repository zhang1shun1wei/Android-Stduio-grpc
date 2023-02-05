package com.mi.car.jsse.easysec.pqc.jcajce.interfaces;

import java.security.PrivateKey;

public interface XMSSPrivateKey extends XMSSKey, PrivateKey {
    XMSSPrivateKey extractKeyShard(int i);

    long getIndex();

    long getUsagesRemaining();
}
