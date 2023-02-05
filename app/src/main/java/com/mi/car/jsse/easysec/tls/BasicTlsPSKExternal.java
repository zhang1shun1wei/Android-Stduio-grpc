package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;

public class BasicTlsPSKExternal implements TlsPSKExternal {
    protected final byte[] identity;
    protected final TlsSecret key;
    protected final int prfAlgorithm;

    public BasicTlsPSKExternal(byte[] identity2, TlsSecret key2) {
        this(identity2, key2, 4);
    }

    public BasicTlsPSKExternal(byte[] identity2, TlsSecret key2, int prfAlgorithm2) {
        this.identity = Arrays.clone(identity2);
        this.key = key2;
        this.prfAlgorithm = prfAlgorithm2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPSK
    public byte[] getIdentity() {
        return this.identity;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPSK
    public TlsSecret getKey() {
        return this.key;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPSK
    public int getPRFAlgorithm() {
        return this.prfAlgorithm;
    }
}
