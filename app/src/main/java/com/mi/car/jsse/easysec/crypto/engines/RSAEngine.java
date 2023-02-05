package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class RSAEngine implements AsymmetricBlockCipher {
    private RSACoreEngine core;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public void init(boolean forEncryption, CipherParameters param) {
        if (this.core == null) {
            this.core = new RSACoreEngine();
        }
        this.core.init(forEncryption, param);
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        return this.core.getInputBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        return this.core.getOutputBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] in, int inOff, int inLen) {
        if (this.core != null) {
            return this.core.convertOutput(this.core.processBlock(this.core.convertInput(in, inOff, inLen)));
        }
        throw new IllegalStateException("RSA engine not initialised");
    }
}
