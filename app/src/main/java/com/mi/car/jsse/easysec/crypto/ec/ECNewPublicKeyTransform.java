package com.mi.car.jsse.easysec.crypto.ec;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ECNewPublicKeyTransform implements ECPairTransform {
    private ECPublicKeyParameters key;
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.ec.ECPairTransform
    public void init(CipherParameters param) {
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom p = (ParametersWithRandom) param;
            if (!(p.getParameters() instanceof ECPublicKeyParameters)) {
                throw new IllegalArgumentException("ECPublicKeyParameters are required for new public key transform.");
            }
            this.key = (ECPublicKeyParameters) p.getParameters();
            this.random = p.getRandom();
        } else if (!(param instanceof ECPublicKeyParameters)) {
            throw new IllegalArgumentException("ECPublicKeyParameters are required for new public key transform.");
        } else {
            this.key = (ECPublicKeyParameters) param;
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.ec.ECPairTransform
    public ECPair transform(ECPair cipherText) {
        if (this.key == null) {
            throw new IllegalStateException("ECNewPublicKeyTransform not initialised");
        }
        ECDomainParameters ec = this.key.getParameters();
        BigInteger n = ec.getN();
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        BigInteger k = ECUtil.generateK(n, this.random);
        ECPoint[] gamma_phi = {basePointMultiplier.multiply(ec.getG(), k), this.key.getQ().multiply(k).add(ECAlgorithms.cleanPoint(ec.getCurve(), cipherText.getY()))};
        ec.getCurve().normalizeAll(gamma_phi);
        return new ECPair(gamma_phi[0], gamma_phi[1]);
    }

    /* access modifiers changed from: protected */
    public ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}
