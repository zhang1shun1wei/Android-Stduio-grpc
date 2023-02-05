package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;
import java.util.Vector;

public class NaccacheSternPrivateKeyParameters extends NaccacheSternKeyParameters {
    private BigInteger phi_n;
    private Vector smallPrimes;

    public NaccacheSternPrivateKeyParameters(BigInteger g, BigInteger n, int lowerSigmaBound, Vector smallPrimes2, BigInteger phi_n2) {
        super(true, g, n, lowerSigmaBound);
        this.smallPrimes = smallPrimes2;
        this.phi_n = phi_n2;
    }

    public BigInteger getPhi_n() {
        return this.phi_n;
    }

    public Vector getSmallPrimes() {
        return this.smallPrimes;
    }
}
