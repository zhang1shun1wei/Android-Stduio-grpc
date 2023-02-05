package com.mi.car.jsse.easysec.pqc.crypto;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;

public class DigestingMessageSigner implements Signer {
    private boolean forSigning;
    private final Digest messDigest;
    private final MessageSigner messSigner;

    public DigestingMessageSigner(MessageSigner messSigner2, Digest messDigest2) {
        this.messSigner = messSigner2;
        this.messDigest = messDigest2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void init(boolean forSigning2, CipherParameters param) {
        AsymmetricKeyParameter k;
        this.forSigning = forSigning2;
        if (param instanceof ParametersWithRandom) {
            k = (AsymmetricKeyParameter) ((ParametersWithRandom) param).getParameters();
        } else {
            k = (AsymmetricKeyParameter) param;
        }
        if (forSigning2 && !k.isPrivate()) {
            throw new IllegalArgumentException("Signing Requires Private Key.");
        } else if (forSigning2 || !k.isPrivate()) {
            reset();
            this.messSigner.init(forSigning2, param);
        } else {
            throw new IllegalArgumentException("Verification Requires Public Key.");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public byte[] generateSignature() {
        if (!this.forSigning) {
            throw new IllegalStateException("DigestingMessageSigner not initialised for signature generation.");
        }
        byte[] hash = new byte[this.messDigest.getDigestSize()];
        this.messDigest.doFinal(hash, 0);
        return this.messSigner.generateSignature(hash);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte b) {
        this.messDigest.update(b);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte[] in, int off, int len) {
        this.messDigest.update(in, off, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void reset() {
        this.messDigest.reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        if (this.forSigning) {
            throw new IllegalStateException("DigestingMessageSigner not initialised for verification");
        }
        byte[] hash = new byte[this.messDigest.getDigestSize()];
        this.messDigest.doFinal(hash, 0);
        return this.messSigner.verifySignature(hash, signature);
    }
}
