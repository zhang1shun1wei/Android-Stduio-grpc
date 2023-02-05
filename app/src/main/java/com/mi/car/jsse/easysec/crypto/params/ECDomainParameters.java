package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;

public class ECDomainParameters implements ECConstants {
    private final ECPoint G;
    private final ECCurve curve;
    private final BigInteger h;
    private BigInteger hInv;
    private final BigInteger n;
    private final byte[] seed;

    public ECDomainParameters(X9ECParameters x9) {
        this(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
    }

    public ECDomainParameters(ECCurve curve2, ECPoint G2, BigInteger n2) {
        this(curve2, G2, n2, ONE, null);
    }

    public ECDomainParameters(ECCurve curve2, ECPoint G2, BigInteger n2, BigInteger h2) {
        this(curve2, G2, n2, h2, null);
    }

    public ECDomainParameters(ECCurve curve2, ECPoint G2, BigInteger n2, BigInteger h2, byte[] seed2) {
        this.hInv = null;
        if (curve2 == null) {
            throw new NullPointerException("curve");
        } else if (n2 == null) {
            throw new NullPointerException("n");
        } else {
            this.curve = curve2;
            this.G = validatePublicPoint(curve2, G2);
            this.n = n2;
            this.h = h2;
            this.seed = Arrays.clone(seed2);
        }
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECPoint getG() {
        return this.G;
    }

    public BigInteger getN() {
        return this.n;
    }

    public BigInteger getH() {
        return this.h;
    }

    public synchronized BigInteger getHInv() {
        if (this.hInv == null) {
            this.hInv = BigIntegers.modOddInverseVar(this.n, this.h);
        }
        return this.hInv;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ECDomainParameters)) {
            return false;
        }
        ECDomainParameters other = (ECDomainParameters) obj;
        return this.curve.equals(other.curve) && this.G.equals(other.G) && this.n.equals(other.n);
    }

    public int hashCode() {
        int hc = 4 * 257;
        return ((((this.curve.hashCode() ^ 1028) * 257) ^ this.G.hashCode()) * 257) ^ this.n.hashCode();
    }

    public BigInteger validatePrivateScalar(BigInteger d) {
        if (d == null) {
            throw new NullPointerException("Scalar cannot be null");
        } else if (d.compareTo(ECConstants.ONE) >= 0 && d.compareTo(getN()) < 0) {
            return d;
        } else {
            throw new IllegalArgumentException("Scalar is not in the interval [1, n - 1]");
        }
    }

    public ECPoint validatePublicPoint(ECPoint q) {
        return validatePublicPoint(getCurve(), q);
    }

    static ECPoint validatePublicPoint(ECCurve c, ECPoint q) {
        if (q == null) {
            throw new NullPointerException("Point cannot be null");
        }
        ECPoint q2 = ECAlgorithms.importPoint(c, q).normalize();
        if (q2.isInfinity()) {
            throw new IllegalArgumentException("Point at infinity");
        } else if (q2.isValid()) {
            return q2;
        } else {
            throw new IllegalArgumentException("Point not on curve");
        }
    }
}
