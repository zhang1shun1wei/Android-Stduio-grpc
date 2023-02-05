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
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ECDSASigner implements ECConstants, DSAExt {
    private final DSAKCalculator kCalculator;
    private ECKeyParameters key;
    private SecureRandom random;

    public ECDSASigner() {
        this.kCalculator = new RandomDSAKCalculator();
    }

    public ECDSASigner(DSAKCalculator kCalculator2) {
        this.kCalculator = kCalculator2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public void init(boolean forSigning, CipherParameters param) {
        SecureRandom providedRandom = null;
        if (!forSigning) {
            this.key = (ECPublicKeyParameters) param;
        } else if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.key = (ECPrivateKeyParameters) rParam.getParameters();
            providedRandom = rParam.getRandom();
        } else {
            this.key = (ECPrivateKeyParameters) param;
        }
        this.random = initSecureRandom(forSigning && !this.kCalculator.isDeterministic(), providedRandom);
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSAExt
    public BigInteger getOrder() {
        return this.key.getParameters().getN();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public BigInteger[] generateSignature(byte[] message) {
        ECDomainParameters ec = this.key.getParameters();
        BigInteger n = ec.getN();
        BigInteger e = calculateE(n, message);
        BigInteger d = ((ECPrivateKeyParameters) this.key).getD();
        if (this.kCalculator.isDeterministic()) {
            this.kCalculator.init(n, d, message);
        } else {
            this.kCalculator.init(n, this.random);
        }
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        while (true) {
            BigInteger k = this.kCalculator.nextK();
            BigInteger r = basePointMultiplier.multiply(ec.getG(), k).normalize().getAffineXCoord().toBigInteger().mod(n);
            if (!r.equals(ZERO)) {
                BigInteger s = BigIntegers.modOddInverse(n, k).multiply(e.add(d.multiply(r))).mod(n);
                if (!s.equals(ZERO)) {
                    return new BigInteger[]{r, s};
                }
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public boolean verifySignature(byte[] message, BigInteger r, BigInteger s) {
        BigInteger cofactor;
        ECFieldElement D;
        ECDomainParameters ec = this.key.getParameters();
        BigInteger n = ec.getN();
        BigInteger e = calculateE(n, message);
        if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0 || s.compareTo(ONE) < 0 || s.compareTo(n) >= 0) {
            return false;
        }
        BigInteger c = BigIntegers.modOddInverseVar(n, s);
        ECPoint point = ECAlgorithms.sumOfTwoMultiplies(ec.getG(), e.multiply(c).mod(n), ((ECPublicKeyParameters) this.key).getQ(), r.multiply(c).mod(n));
        if (point.isInfinity()) {
            return false;
        }
        ECCurve curve = point.getCurve();
        if (curve == null || (cofactor = curve.getCofactor()) == null || cofactor.compareTo(EIGHT) > 0 || (D = getDenominator(curve.getCoordinateSystem(), point)) == null || D.isZero()) {
            return point.normalize().getAffineXCoord().toBigInteger().mod(n).equals(r);
        }
        ECFieldElement X = point.getXCoord();
        while (curve.isValidFieldElement(r)) {
            if (curve.fromBigInteger(r).multiply(D).equals(X)) {
                return true;
            }
            r = r.add(n);
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public BigInteger calculateE(BigInteger n, byte[] message) {
        int log2n = n.bitLength();
        int messageBitLength = message.length * 8;
        BigInteger e = new BigInteger(1, message);
        if (log2n < messageBitLength) {
            return e.shiftRight(messageBitLength - log2n);
        }
        return e;
    }

    /* access modifiers changed from: protected */
    public ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    /* access modifiers changed from: protected */
    public ECFieldElement getDenominator(int coordinateSystem, ECPoint p) {
        switch (coordinateSystem) {
            case 1:
            case 6:
            case 7:
                return p.getZCoord(0);
            case 2:
            case 3:
            case 4:
                return p.getZCoord(0).square();
            case 5:
            default:
                return null;
        }
    }

    /* access modifiers changed from: protected */
    public SecureRandom initSecureRandom(boolean needed, SecureRandom provided) {
        if (needed) {
            return CryptoServicesRegistrar.getSecureRandom(provided);
        }
        return null;
    }
}
