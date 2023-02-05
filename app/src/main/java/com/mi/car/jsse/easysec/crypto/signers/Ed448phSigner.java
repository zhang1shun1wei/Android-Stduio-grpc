package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.params.Ed448PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed448PublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.rfc8032.Ed448;
import com.mi.car.jsse.easysec.util.Arrays;

public class Ed448phSigner implements Signer {
    private final byte[] context;
    private boolean forSigning;
    private final Xof prehash = Ed448.createPrehash();
    private Ed448PrivateKeyParameters privateKey;
    private Ed448PublicKeyParameters publicKey;

    public Ed448phSigner(byte[] context2) {
        this.context = Arrays.clone(context2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void init(boolean forSigning2, CipherParameters parameters) {
        this.forSigning = forSigning2;
        if (forSigning2) {
            this.privateKey = (Ed448PrivateKeyParameters) parameters;
            this.publicKey = null;
        } else {
            this.privateKey = null;
            this.publicKey = (Ed448PublicKeyParameters) parameters;
        }
        reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte b) {
        this.prehash.update(b);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte[] buf, int off, int len) {
        this.prehash.update(buf, off, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public byte[] generateSignature() {
        if (!this.forSigning || this.privateKey == null) {
            throw new IllegalStateException("Ed448phSigner not initialised for signature generation.");
        }
        byte[] msg = new byte[64];
        if (64 != this.prehash.doFinal(msg, 0, 64)) {
            throw new IllegalStateException("Prehash digest failed");
        }
        byte[] signature = new byte[114];
        this.privateKey.sign(1, this.context, msg, 0, 64, signature, 0);
        return signature;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        if (this.forSigning || this.publicKey == null) {
            throw new IllegalStateException("Ed448phSigner not initialised for verification");
        } else if (114 == signature.length) {
            return Ed448.verifyPrehash(signature, 0, this.publicKey.getEncoded(), 0, this.context, this.prehash);
        } else {
            this.prehash.reset();
            return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void reset() {
        this.prehash.reset();
    }
}
