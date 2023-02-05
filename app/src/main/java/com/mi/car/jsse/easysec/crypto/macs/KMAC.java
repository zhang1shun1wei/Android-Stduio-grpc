package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.CSHAKEDigest;
import com.mi.car.jsse.easysec.crypto.digests.XofUtils;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;

public class KMAC implements Mac, Xof {
    private static final byte[] padding = new byte[100];
    private final int bitLength;
    private final CSHAKEDigest cshake;
    private boolean firstOutput;
    private boolean initialised;
    private byte[] key;
    private final int outputLength;

    public KMAC(int bitLength2, byte[] S) {
        this.cshake = new CSHAKEDigest(bitLength2, Strings.toByteArray("KMAC"), S);
        this.bitLength = bitLength2;
        this.outputLength = (bitLength2 * 2) / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters params) throws IllegalArgumentException {
        this.key = Arrays.clone(((KeyParameter) params).getKey());
        this.initialised = true;
        reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "KMAC" + this.cshake.getAlgorithmName().substring(6);
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return this.cshake.getByteLength();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return this.outputLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.outputLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) throws IllegalStateException {
        if (!this.initialised) {
            throw new IllegalStateException("KMAC not initialized");
        }
        this.cshake.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        if (!this.initialised) {
            throw new IllegalStateException("KMAC not initialized");
        }
        this.cshake.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.firstOutput) {
            if (!this.initialised) {
                throw new IllegalStateException("KMAC not initialized");
            }
            byte[] encOut = XofUtils.rightEncode((long) (getMacSize() * 8));
            this.cshake.update(encOut, 0, encOut.length);
        }
        int rv = this.cshake.doFinal(out, outOff, getMacSize());
        reset();
        return rv;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doFinal(byte[] out, int outOff, int outLen) {
        if (this.firstOutput) {
            if (!this.initialised) {
                throw new IllegalStateException("KMAC not initialized");
            }
            byte[] encOut = XofUtils.rightEncode((long) (outLen * 8));
            this.cshake.update(encOut, 0, encOut.length);
        }
        int rv = this.cshake.doFinal(out, outOff, outLen);
        reset();
        return rv;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doOutput(byte[] out, int outOff, int outLen) {
        if (this.firstOutput) {
            if (!this.initialised) {
                throw new IllegalStateException("KMAC not initialized");
            }
            byte[] encOut = XofUtils.rightEncode(0);
            this.cshake.update(encOut, 0, encOut.length);
            this.firstOutput = false;
        }
        return this.cshake.doOutput(out, outOff, outLen);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.cshake.reset();
        if (this.key != null) {
            if (this.bitLength == 128) {
                bytePad(this.key, 168);
            } else {
                bytePad(this.key, 136);
            }
        }
        this.firstOutput = true;
    }

    private void bytePad(byte[] X, int w) {
        byte[] bytes = XofUtils.leftEncode((long) w);
        update(bytes, 0, bytes.length);
        byte[] encX = encode(X);
        update(encX, 0, encX.length);
        int required = w - ((bytes.length + encX.length) % w);
        if (required > 0 && required != w) {
            while (required > padding.length) {
                update(padding, 0, padding.length);
                required -= padding.length;
            }
            update(padding, 0, required);
        }
    }

    private static byte[] encode(byte[] X) {
        return Arrays.concatenate(XofUtils.leftEncode((long) (X.length * 8)), X);
    }
}
