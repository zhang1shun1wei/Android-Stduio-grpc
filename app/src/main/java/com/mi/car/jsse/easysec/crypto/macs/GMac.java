package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.modes.GCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;

public class GMac implements Mac {
    private final GCMBlockCipher cipher;
    private final int macSizeBits;

    public GMac(GCMBlockCipher cipher2) {
        this.cipher = cipher2;
        this.macSizeBits = 128;
    }

    public GMac(GCMBlockCipher cipher2, int macSizeBits2) {
        this.cipher = cipher2;
        this.macSizeBits = macSizeBits2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters params) throws IllegalArgumentException {
        if (params instanceof ParametersWithIV) {
            ParametersWithIV param = (ParametersWithIV) params;
            this.cipher.init(true, new AEADParameters((KeyParameter) param.getParameters(), this.macSizeBits, param.getIV()));
            return;
        }
        throw new IllegalArgumentException("GMAC requires ParametersWithIV");
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return this.cipher.getUnderlyingCipher().getAlgorithmName() + "-GMAC";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return this.macSizeBits / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte in) throws IllegalStateException {
        this.cipher.processAADByte(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        this.cipher.processAADBytes(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        try {
            return this.cipher.doFinal(out, outOff);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException(e.toString());
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void reset() {
        this.cipher.reset();
    }
}
