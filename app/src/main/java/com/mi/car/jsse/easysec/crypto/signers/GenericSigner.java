package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.util.Arrays;

public class GenericSigner implements Signer {
    private final Digest digest;
    private final AsymmetricBlockCipher engine;
    private boolean forSigning;

    public GenericSigner(AsymmetricBlockCipher engine2, Digest digest2) {
        this.engine = engine2;
        this.digest = digest2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void init(boolean forSigning2, CipherParameters parameters) {
        AsymmetricKeyParameter k;
        this.forSigning = forSigning2;
        if (parameters instanceof ParametersWithRandom) {
            k = (AsymmetricKeyParameter) ((ParametersWithRandom) parameters).getParameters();
        } else {
            k = (AsymmetricKeyParameter) parameters;
        }
        if (forSigning2 && !k.isPrivate()) {
            throw new IllegalArgumentException("signing requires private key");
        } else if (forSigning2 || !k.isPrivate()) {
            reset();
            this.engine.init(forSigning2, parameters);
        } else {
            throw new IllegalArgumentException("verification requires public key");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte input) {
        this.digest.update(input);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte[] input, int inOff, int length) {
        this.digest.update(input, inOff, length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public byte[] generateSignature() throws CryptoException, DataLengthException {
        if (!this.forSigning) {
            throw new IllegalStateException("GenericSigner not initialised for signature generation.");
        }
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        return this.engine.processBlock(hash, 0, hash.length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        if (this.forSigning) {
            throw new IllegalStateException("GenericSigner not initialised for verification");
        }
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            byte[] sig = this.engine.processBlock(signature, 0, signature.length);
            if (sig.length < hash.length) {
                byte[] tmp = new byte[hash.length];
                System.arraycopy(sig, 0, tmp, tmp.length - sig.length, sig.length);
                sig = tmp;
            }
            return Arrays.constantTimeAreEqual(sig, hash);
        } catch (Exception e) {
            return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void reset() {
        this.digest.reset();
    }
}
