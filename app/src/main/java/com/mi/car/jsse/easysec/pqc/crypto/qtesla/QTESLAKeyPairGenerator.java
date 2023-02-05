package com.mi.car.jsse.easysec.pqc.crypto.qtesla;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import java.security.SecureRandom;

public final class QTESLAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SecureRandom secureRandom;
    private int securityCategory;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        QTESLAKeyGenerationParameters parameters = (QTESLAKeyGenerationParameters) param;
        this.secureRandom = parameters.getRandom();
        this.securityCategory = parameters.getSecurityCategory();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        byte[] privateKey = allocatePrivate(this.securityCategory);
        byte[] publicKey = allocatePublic(this.securityCategory);
        switch (this.securityCategory) {
            case 5:
                QTesla1p.generateKeyPair(publicKey, privateKey, this.secureRandom);
                break;
            case 6:
                QTesla3p.generateKeyPair(publicKey, privateKey, this.secureRandom);
                break;
            default:
                throw new IllegalArgumentException("unknown security category: " + this.securityCategory);
        }
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new QTESLAPublicKeyParameters(this.securityCategory, publicKey), (AsymmetricKeyParameter) new QTESLAPrivateKeyParameters(this.securityCategory, privateKey));
    }

    private byte[] allocatePrivate(int securityCategory2) {
        return new byte[QTESLASecurityCategory.getPrivateSize(securityCategory2)];
    }

    private byte[] allocatePublic(int securityCategory2) {
        return new byte[QTESLASecurityCategory.getPublicSize(securityCategory2)];
    }
}
