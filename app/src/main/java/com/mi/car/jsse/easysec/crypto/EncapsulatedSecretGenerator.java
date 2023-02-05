package com.mi.car.jsse.easysec.crypto;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public interface EncapsulatedSecretGenerator {
    SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter asymmetricKeyParameter);
}
