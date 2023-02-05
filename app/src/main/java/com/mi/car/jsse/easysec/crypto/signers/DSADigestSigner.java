package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DSA;
import com.mi.car.jsse.easysec.crypto.DSAExt;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import java.math.BigInteger;

public class DSADigestSigner implements Signer {
    private final Digest digest;
    private final DSA dsa;
    private final DSAEncoding encoding;
    private boolean forSigning;

    public DSADigestSigner(DSA dsa2, Digest digest2) {
        this.dsa = dsa2;
        this.digest = digest2;
        this.encoding = StandardDSAEncoding.INSTANCE;
    }

    public DSADigestSigner(DSAExt dsa2, Digest digest2, DSAEncoding encoding2) {
        this.dsa = dsa2;
        this.digest = digest2;
        this.encoding = encoding2;
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
            throw new IllegalArgumentException("Signing Requires Private Key.");
        } else if (forSigning2 || !k.isPrivate()) {
            reset();
            this.dsa.init(forSigning2, parameters);
        } else {
            throw new IllegalArgumentException("Verification Requires Public Key.");
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
    public byte[] generateSignature() {
        if (!this.forSigning) {
            throw new IllegalStateException("DSADigestSigner not initialised for signature generation.");
        }
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        BigInteger[] sig = this.dsa.generateSignature(hash);
        try {
            return this.encoding.encode(getOrder(), sig[0], sig[1]);
        } catch (Exception e) {
            throw new IllegalStateException("unable to encode signature");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        if (this.forSigning) {
            throw new IllegalStateException("DSADigestSigner not initialised for verification");
        }
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            BigInteger[] sig = this.encoding.decode(getOrder(), signature);
            return this.dsa.verifySignature(hash, sig[0], sig[1]);
        } catch (Exception e) {
            return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void reset() {
        this.digest.reset();
    }

    /* access modifiers changed from: protected */
    public BigInteger getOrder() {
        if (this.dsa instanceof DSAExt) {
            return ((DSAExt) this.dsa).getOrder();
        }
        return null;
    }
}
