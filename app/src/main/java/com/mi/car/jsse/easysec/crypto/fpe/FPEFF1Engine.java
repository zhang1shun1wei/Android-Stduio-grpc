package com.mi.car.jsse.easysec.crypto.fpe;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.engines.AESEngine;
import com.mi.car.jsse.easysec.crypto.params.FPEParameters;
import com.mi.car.jsse.easysec.util.Properties;

public class FPEFF1Engine extends FPEEngine {
    public FPEFF1Engine() {
        this(new AESEngine());
    }

    public FPEFF1Engine(BlockCipher baseCipher) {
        super(baseCipher);
        if (baseCipher.getBlockSize() != 16) {
            throw new IllegalArgumentException("base cipher needs to be 128 bits");
        } else if (Properties.isOverrideSet("com.mi.car.jsse.easysec.fpe.disable") || Properties.isOverrideSet("com.mi.car.jsse.easysec.fpe.disable_ff1")) {
            throw new UnsupportedOperationException("FF1 encryption disabled");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.fpe.FPEEngine
    public void init(boolean forEncryption, CipherParameters parameters) {
        this.forEncryption = forEncryption;
        this.fpeParameters = (FPEParameters) parameters;
        this.baseCipher.init(!this.fpeParameters.isUsingInverseFunction(), this.fpeParameters.getKey());
    }

    @Override // com.mi.car.jsse.easysec.crypto.fpe.FPEEngine
    public String getAlgorithmName() {
        return "FF1";
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.fpe.FPEEngine
    public int encryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff) {
        byte[] enc;
        if (this.fpeParameters.getRadix() > 256) {
            enc = toByteArray(SP80038G.encryptFF1w(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), toShortArray(inBuf), inOff, length / 2));
        } else {
            enc = SP80038G.encryptFF1(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), inBuf, inOff, length);
        }
        System.arraycopy(enc, 0, outBuf, outOff, length);
        return length;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.fpe.FPEEngine
    public int decryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff) {
        byte[] dec;
        if (this.fpeParameters.getRadix() > 256) {
            dec = toByteArray(SP80038G.decryptFF1w(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), toShortArray(inBuf), inOff, length / 2));
        } else {
            dec = SP80038G.decryptFF1(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), inBuf, inOff, length);
        }
        System.arraycopy(dec, 0, outBuf, outOff, length);
        return length;
    }
}
