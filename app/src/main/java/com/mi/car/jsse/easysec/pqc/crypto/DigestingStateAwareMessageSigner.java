package com.mi.car.jsse.easysec.pqc.crypto;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class DigestingStateAwareMessageSigner extends DigestingMessageSigner {
    private final StateAwareMessageSigner signer;

    public DigestingStateAwareMessageSigner(StateAwareMessageSigner messSigner, Digest messDigest) {
        super(messSigner, messDigest);
        this.signer = messSigner;
    }

    public AsymmetricKeyParameter getUpdatedPrivateKey() {
        return this.signer.getUpdatedPrivateKey();
    }
}
