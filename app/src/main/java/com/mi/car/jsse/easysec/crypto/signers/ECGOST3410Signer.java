package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DSAExt;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ECGOST3410Signer implements DSAExt {
    ECKeyParameters key;
    SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public void init(boolean forSigning, CipherParameters param) {
        if (!forSigning) {
            this.key = (ECPublicKeyParameters) param;
        } else if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.random = rParam.getRandom();
            this.key = (ECPrivateKeyParameters) rParam.getParameters();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.key = (ECPrivateKeyParameters) param;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSAExt
    public BigInteger getOrder() {
        return this.key.getParameters().getN();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public BigInteger[] generateSignature(byte[] message) {
        BigInteger e = new BigInteger(1, Arrays.reverse(message));
        ECDomainParameters ec = this.key.getParameters();
        BigInteger n = ec.getN();
        BigInteger d = ((ECPrivateKeyParameters) this.key).getD();
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        while (true) {
            BigInteger k = BigIntegers.createRandomBigInteger(n.bitLength(), this.random);
            if (!k.equals(ECConstants.ZERO)) {
                BigInteger r = basePointMultiplier.multiply(ec.getG(), k).normalize().getAffineXCoord().toBigInteger().mod(n);
                if (!r.equals(ECConstants.ZERO)) {
                    BigInteger s = k.multiply(e).add(d.multiply(r)).mod(n);
                    if (!s.equals(ECConstants.ZERO)) {
                        return new BigInteger[]{r, s};
                    }
                } else {
                    continue;
                }
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public boolean verifySignature(byte[] message, BigInteger r, BigInteger s) {
        BigInteger e = new BigInteger(1, Arrays.reverse(message));
        BigInteger n = this.key.getParameters().getN();
        if (r.compareTo(ECConstants.ONE) < 0 || r.compareTo(n) >= 0) {
            return false;
        }
        if (s.compareTo(ECConstants.ONE) < 0 || s.compareTo(n) >= 0) {
            return false;
        }
        BigInteger v = BigIntegers.modOddInverseVar(n, e);
        ECPoint point = ECAlgorithms.sumOfTwoMultiplies(this.key.getParameters().getG(), s.multiply(v).mod(n), ((ECPublicKeyParameters) this.key).getQ(), n.subtract(r).multiply(v).mod(n)).normalize();
        if (point.isInfinity()) {
            return false;
        }
        return point.getAffineXCoord().toBigInteger().mod(n).equals(r);
    }

    /* access modifiers changed from: protected */
    public ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}
