package com.mi.car.jsse.easysec.pqc.jcajce.interfaces;

import java.security.PrivateKey;

public interface XMSSMTPrivateKey extends XMSSMTKey, PrivateKey {
    XMSSMTPrivateKey extractKeyShard(int i);

    long getIndex();

    long getUsagesRemaining();
}
