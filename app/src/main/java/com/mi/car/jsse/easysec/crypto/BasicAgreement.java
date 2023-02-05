package com.mi.car.jsse.easysec.crypto;

import java.math.BigInteger;

public interface BasicAgreement {
    BigInteger calculateAgreement(CipherParameters cipherParameters);

    int getFieldSize();

    void init(CipherParameters cipherParameters);
}
