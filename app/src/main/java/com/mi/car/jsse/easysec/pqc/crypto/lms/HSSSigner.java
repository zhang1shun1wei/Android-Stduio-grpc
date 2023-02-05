package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.MessageSigner;
import java.io.IOException;

public class HSSSigner implements MessageSigner {
    private HSSPrivateKeyParameters privKey;
    private HSSPublicKeyParameters pubKey;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.privKey = (HSSPrivateKeyParameters) param;
        } else {
            this.pubKey = (HSSPublicKeyParameters) param;
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        try {
            return HSS.generateSignature(this.privKey, message).getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage());
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        try {
            return HSS.verifySignature(this.pubKey, HSSSignature.getInstance(signature, this.pubKey.getL()), message);
        } catch (IOException e) {
            throw new IllegalStateException("unable to decode signature: " + e.getMessage());
        }
    }
}
