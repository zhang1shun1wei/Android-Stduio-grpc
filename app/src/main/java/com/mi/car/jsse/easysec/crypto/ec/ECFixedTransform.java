package com.mi.car.jsse.easysec.crypto.ec;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;
import java.math.BigInteger;

public class ECFixedTransform implements ECPairFactorTransform {
    private BigInteger k;
    private ECPublicKeyParameters key;

    public ECFixedTransform(BigInteger k2) {
        this.k = k2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.ec.ECPairTransform
    public void init(CipherParameters param) {
        if (!(param instanceof ECPublicKeyParameters)) {
            throw new IllegalArgumentException("ECPublicKeyParameters are required for fixed transform.");
        }
        this.key = (ECPublicKeyParameters) param;
    }

    @Override // com.mi.car.jsse.easysec.crypto.ec.ECPairTransform
    public ECPair transform(ECPair cipherText) {
        if (this.key == null) {
            throw new IllegalStateException("ECFixedTransform not initialised");
        }
        ECDomainParameters ec = this.key.getParameters();
        BigInteger n = ec.getN();
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        BigInteger k2 = this.k.mod(n);
        ECPoint[] gamma_phi = {basePointMultiplier.multiply(ec.getG(), k2).add(ECAlgorithms.cleanPoint(ec.getCurve(), cipherText.getX())), this.key.getQ().multiply(k2).add(ECAlgorithms.cleanPoint(ec.getCurve(), cipherText.getY()))};
        ec.getCurve().normalizeAll(gamma_phi);
        return new ECPair(gamma_phi[0], gamma_phi[1]);
    }

    @Override // com.mi.car.jsse.easysec.crypto.ec.ECPairFactorTransform
    public BigInteger getTransformValue() {
        return this.k;
    }

    /* access modifiers changed from: protected */
    public ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}
