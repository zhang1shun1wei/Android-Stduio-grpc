package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.DerivationFunction;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.crypto.params.HKDFParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public class HKDFBytesGenerator implements DerivationFunction {
    private byte[] currentT;
    private int generatedBytes;
    private HMac hMacHash;
    private int hashLen;
    private byte[] info;

    public HKDFBytesGenerator(Digest hash) {
        this.hMacHash = new HMac(hash);
        this.hashLen = hash.getDigestSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public void init(DerivationParameters param) {
        if (!(param instanceof HKDFParameters)) {
            throw new IllegalArgumentException("HKDF parameters required for HKDFBytesGenerator");
        }
        HKDFParameters params = (HKDFParameters) param;
        if (params.skipExtract()) {
            this.hMacHash.init(new KeyParameter(params.getIKM()));
        } else {
            this.hMacHash.init(extract(params.getSalt(), params.getIKM()));
        }
        this.info = params.getInfo();
        this.generatedBytes = 0;
        this.currentT = new byte[this.hashLen];
    }

    private KeyParameter extract(byte[] salt, byte[] ikm) {
        if (salt == null) {
            this.hMacHash.init(new KeyParameter(new byte[this.hashLen]));
        } else {
            this.hMacHash.init(new KeyParameter(salt));
        }
        this.hMacHash.update(ikm, 0, ikm.length);
        byte[] prk = new byte[this.hashLen];
        this.hMacHash.doFinal(prk, 0);
        return new KeyParameter(prk);
    }

    private void expandNext() throws DataLengthException {
        int n = (this.generatedBytes / this.hashLen) + 1;
        if (n >= 256) {
            throw new DataLengthException("HKDF cannot generate more than 255 blocks of HashLen size");
        }
        if (this.generatedBytes != 0) {
            this.hMacHash.update(this.currentT, 0, this.hashLen);
        }
        this.hMacHash.update(this.info, 0, this.info.length);
        this.hMacHash.update((byte) n);
        this.hMacHash.doFinal(this.currentT, 0);
    }

    public Digest getDigest() {
        return this.hMacHash.getUnderlyingDigest();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        if (this.generatedBytes + len > this.hashLen * GF2Field.MASK) {
            throw new DataLengthException("HKDF may only be used for 255 * HashLen bytes of output");
        }
        if (this.generatedBytes % this.hashLen == 0) {
            expandNext();
        }
        int posInT = this.generatedBytes % this.hashLen;
        int toCopy = Math.min(this.hashLen - (this.generatedBytes % this.hashLen), len);
        System.arraycopy(this.currentT, posInT, out, outOff, toCopy);
        this.generatedBytes += toCopy;
        int toGenerate = len - toCopy;
        int outOff2 = outOff + toCopy;
        while (toGenerate > 0) {
            expandNext();
            int toCopy2 = Math.min(this.hashLen, toGenerate);
            System.arraycopy(this.currentT, 0, out, outOff2, toCopy2);
            this.generatedBytes += toCopy2;
            toGenerate -= toCopy2;
            outOff2 += toCopy2;
        }
        return len;
    }
}
