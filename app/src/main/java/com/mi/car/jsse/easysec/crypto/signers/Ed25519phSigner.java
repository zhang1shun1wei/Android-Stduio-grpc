package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.rfc8032.Ed25519;
import com.mi.car.jsse.easysec.util.Arrays;

public class Ed25519phSigner implements Signer {
    private final byte[] context;
    private boolean forSigning;
    private final Digest prehash = Ed25519.createPrehash();
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    public Ed25519phSigner(byte[] context2) {
        this.context = Arrays.clone(context2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void init(boolean forSigning2, CipherParameters parameters) {
        this.forSigning = forSigning2;
        if (forSigning2) {
            this.privateKey = (Ed25519PrivateKeyParameters) parameters;
            this.publicKey = null;
        } else {
            this.privateKey = null;
            this.publicKey = (Ed25519PublicKeyParameters) parameters;
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
            throw new IllegalStateException("Ed25519phSigner not initialised for signature generation.");
        }
        byte[] msg = new byte[64];
        if (64 != this.prehash.doFinal(msg, 0)) {
            throw new IllegalStateException("Prehash digest failed");
        }
        byte[] signature = new byte[64];
        this.privateKey.sign(2, this.context, msg, 0, 64, signature, 0);
        return signature;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        if (this.forSigning || this.publicKey == null) {
            throw new IllegalStateException("Ed25519phSigner not initialised for verification");
        } else if (64 == signature.length) {
            return Ed25519.verifyPrehash(signature, 0, this.publicKey.getEncoded(), 0, this.context, this.prehash);
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
