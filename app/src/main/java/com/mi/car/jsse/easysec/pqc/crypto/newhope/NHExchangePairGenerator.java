package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.ExchangePair;
import com.mi.car.jsse.easysec.pqc.crypto.ExchangePairGenerator;
import java.security.SecureRandom;

public class NHExchangePairGenerator implements ExchangePairGenerator {
    private final SecureRandom random;

    public NHExchangePairGenerator(SecureRandom random2) {
        this.random = random2;
    }

    public ExchangePair GenerateExchange(AsymmetricKeyParameter senderPublicKey) {
        return generateExchange(senderPublicKey);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.ExchangePairGenerator
    public ExchangePair generateExchange(AsymmetricKeyParameter senderPublicKey) {
        byte[] sharedValue = new byte[32];
        byte[] publicKeyValue = new byte[2048];
        NewHope.sharedB(this.random, sharedValue, publicKeyValue, ((NHPublicKeyParameters) senderPublicKey).pubData);
        return new ExchangePair(new NHPublicKeyParameters(publicKeyValue), sharedValue);
    }
}
