package com.mi.car.jsse.easysec.tls.crypto;

public class TlsDHConfig {
    protected final DHGroup explicitGroup;
    protected final int namedGroup;
    protected final boolean padded;

    public TlsDHConfig(DHGroup explicitGroup2) {
        this.explicitGroup = explicitGroup2;
        this.namedGroup = -1;
        this.padded = false;
    }

    public TlsDHConfig(int namedGroup2, boolean padded2) {
        this.explicitGroup = null;
        this.namedGroup = namedGroup2;
        this.padded = padded2;
    }

    public DHGroup getExplicitGroup() {
        return this.explicitGroup;
    }

    public int getNamedGroup() {
        return this.namedGroup;
    }

    public boolean isPadded() {
        return this.padded;
    }
}
