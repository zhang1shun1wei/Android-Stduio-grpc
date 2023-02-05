package com.mi.car.jsse.easysec.pqc.crypto;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public interface StateAwareMessageSigner extends MessageSigner {
    AsymmetricKeyParameter getUpdatedPrivateKey();
}
