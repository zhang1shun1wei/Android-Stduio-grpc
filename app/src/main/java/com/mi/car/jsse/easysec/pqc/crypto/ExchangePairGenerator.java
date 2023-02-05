package com.mi.car.jsse.easysec.pqc.crypto;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public interface ExchangePairGenerator {
    ExchangePair generateExchange(AsymmetricKeyParameter asymmetricKeyParameter);
}
