package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.Xof;

public class SHAKEDigest extends KeccakDigest implements Xof {
    private static int checkBitLength(int bitLength) {
        switch (bitLength) {
            case 128:
            case 256:
                return bitLength;
            default:
                throw new IllegalArgumentException("'bitLength' " + bitLength + " not supported for SHAKE");
        }
    }

    public SHAKEDigest() {
        this(128);
    }

    public SHAKEDigest(int bitLength) {
        super(checkBitLength(bitLength));
    }

    public SHAKEDigest(SHAKEDigest source) {
        super(source);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public String getAlgorithmName() {
        return "SHAKE" + this.fixedOutputLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public int getDigestSize() {
        return this.fixedOutputLength / 4;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public int doFinal(byte[] out, int outOff) {
        return doFinal(out, outOff, getDigestSize());
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doFinal(byte[] out, int outOff, int outLen) {
        int length = doOutput(out, outOff, outLen);
        reset();
        return length;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doOutput(byte[] out, int outOff, int outLen) {
        if (!this.squeezing) {
            absorbBits(15, 4);
        }
        squeeze(out, outOff, ((long) outLen) * 8);
        return outLen;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public int doFinal(byte[] out, int outOff, byte partialByte, int partialBits) {
        return doFinal(out, outOff, getDigestSize(), partialByte, partialBits);
    }

    /* access modifiers changed from: protected */
    public int doFinal(byte[] out, int outOff, int outLen, byte partialByte, int partialBits) {
        if (partialBits < 0 || partialBits > 7) {
            throw new IllegalArgumentException("'partialBits' must be in the range [0,7]");
        }
        int finalInput = (((1 << partialBits) - 1) & partialByte) | (15 << partialBits);
        int finalBits = partialBits + 4;
        if (finalBits >= 8) {
            absorb((byte) finalInput);
            finalBits -= 8;
            finalInput >>>= 8;
        }
        if (finalBits > 0) {
            absorbBits(finalInput, finalBits);
        }
        squeeze(out, outOff, ((long) outLen) * 8);
        reset();
        return outLen;
    }
}
