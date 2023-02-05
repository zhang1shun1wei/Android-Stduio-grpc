package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithUKM;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;

public class ECVKOAgreement {
    private final Digest digest;
    private ECPrivateKeyParameters key;
    private BigInteger ukm;

    public ECVKOAgreement(Digest digest2) {
        this.digest = digest2;
    }

    public void init(CipherParameters key2) {
        ParametersWithUKM p = (ParametersWithUKM) key2;
        this.key = (ECPrivateKeyParameters) p.getParameters();
        this.ukm = toInteger(p.getUKM());
    }

    public int getFieldSize() {
        return (this.key.getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey) {
        ECPublicKeyParameters pub = (ECPublicKeyParameters) pubKey;
        ECDomainParameters params = this.key.getParameters();
        if (!params.equals(pub.getParameters())) {
            throw new IllegalStateException("ECVKO public key has wrong domain parameters");
        }
        BigInteger hd = params.getH().multiply(this.ukm).multiply(this.key.getD()).mod(params.getN());
        ECPoint pubPoint = ECAlgorithms.cleanPoint(params.getCurve(), pub.getQ());
        if (pubPoint.isInfinity()) {
            throw new IllegalStateException("Infinity is not a valid public key for ECDHC");
        }
        ECPoint P = pubPoint.multiply(hd).normalize();
        if (!P.isInfinity()) {
            return fromPoint(P);
        }
        throw new IllegalStateException("Infinity is not a valid agreement value for ECVKO");
    }

    private static BigInteger toInteger(byte[] ukm2) {
        byte[] v = new byte[ukm2.length];
        for (int i = 0; i != v.length; i++) {
            v[i] = ukm2[(ukm2.length - i) - 1];
        }
        return new BigInteger(1, v);
    }

    private byte[] fromPoint(ECPoint v) {
        int size;
        BigInteger bX = v.getAffineXCoord().toBigInteger();
        BigInteger bY = v.getAffineYCoord().toBigInteger();
        if (bX.toByteArray().length > 33) {
            size = 64;
        } else {
            size = 32;
        }
        byte[] bytes = new byte[(size * 2)];
        byte[] x = BigIntegers.asUnsignedByteArray(size, bX);
        byte[] y = BigIntegers.asUnsignedByteArray(size, bY);
        for (int i = 0; i != size; i++) {
            bytes[i] = x[(size - i) - 1];
        }
        for (int i2 = 0; i2 != size; i2++) {
            bytes[size + i2] = y[(size - i2) - 1];
        }
        this.digest.update(bytes, 0, bytes.length);
        byte[] rv = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(rv, 0);
        return rv;
    }
}
