package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.MessageSigner;
import java.io.IOException;

public class LMSSigner implements MessageSigner {
    private LMSPrivateKeyParameters privKey;
    private LMSPublicKeyParameters pubKey;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.privKey = (LMSPrivateKeyParameters) param;
        } else {
            this.pubKey = (LMSPublicKeyParameters) param;
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        try {
            return LMS.generateSign(this.privKey, message).getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage());
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        try {
            return LMS.verifySignature(this.pubKey, LMSSignature.getInstance(signature), message);
        } catch (IOException e) {
            throw new IllegalStateException("unable to decode signature: " + e.getMessage());
        }
    }
}
