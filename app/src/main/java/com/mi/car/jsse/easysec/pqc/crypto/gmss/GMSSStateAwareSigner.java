package com.mi.car.jsse.easysec.pqc.crypto.gmss;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.StateAwareMessageSigner;
import com.mi.car.jsse.easysec.util.Memoable;

public class GMSSStateAwareSigner implements StateAwareMessageSigner {
    private final GMSSSigner gmssSigner;
    private GMSSPrivateKeyParameters key;

    public GMSSStateAwareSigner(Digest digest) {
        if (!(digest instanceof Memoable)) {
            throw new IllegalArgumentException("digest must implement Memoable");
        }
        final Memoable dig = ((Memoable) digest).copy();
        this.gmssSigner = new GMSSSigner(new GMSSDigestProvider() {
            /* class com.mi.car.jsse.easysec.pqc.crypto.gmss.GMSSStateAwareSigner.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.pqc.crypto.gmss.GMSSDigestProvider
            public Digest get() {
                return (Digest) dig.copy();
            }
        });
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            if (param instanceof ParametersWithRandom) {
                this.key = (GMSSPrivateKeyParameters) ((ParametersWithRandom) param).getParameters();
            } else {
                this.key = (GMSSPrivateKeyParameters) param;
            }
        }
        this.gmssSigner.init(forSigning, param);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        if (this.key == null) {
            throw new IllegalStateException("signing key no longer usable");
        }
        byte[] sig = this.gmssSigner.generateSignature(message);
        this.key = this.key.nextKey();
        return sig;
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        return this.gmssSigner.verifySignature(message, signature);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.StateAwareMessageSigner
    public AsymmetricKeyParameter getUpdatedPrivateKey() {
        AsymmetricKeyParameter k = this.key;
        this.key = null;
        return k;
    }
}
