package com.mi.car.jsse.easysec.crypto;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public interface StagedAgreement extends BasicAgreement {
    AsymmetricKeyParameter calculateStage(CipherParameters cipherParameters);
}
