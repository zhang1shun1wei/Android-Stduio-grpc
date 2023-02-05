package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;

public class DSTU4145KeyPairGenerator extends ECKeyPairGenerator {
    @Override // com.mi.car.jsse.easysec.crypto.generators.ECKeyPairGenerator, com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        AsymmetricCipherKeyPair pair = super.generateKeyPair();
        ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new ECPublicKeyParameters(pub.getQ().negate(), pub.getParameters()), (AsymmetricKeyParameter) ((ECPrivateKeyParameters) pair.getPrivate()));
    }
}
