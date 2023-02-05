package com.mi.car.jsse.easysec.tls.crypto;

public class TlsECConfig {
    protected final int namedGroup;

    public TlsECConfig(int namedGroup2) {
        this.namedGroup = namedGroup2;
    }

    public int getNamedGroup() {
        return this.namedGroup;
    }
}
