package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.asn1.BERTags;

public class SHA3Digest extends KeccakDigest {
    private static int checkBitLength(int bitLength) {
        switch (bitLength) {
            case BERTags.FLAGS:
            case 256:
            case 384:
            case 512:
                return bitLength;
            default:
                throw new IllegalArgumentException("'bitLength' " + bitLength + " not supported for SHA-3");
        }
    }

    public SHA3Digest() {
        this(256);
    }

    public SHA3Digest(int bitLength) {
        super(checkBitLength(bitLength));
    }

    public SHA3Digest(SHA3Digest source) {
        super(source);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public String getAlgorithmName() {
        return "SHA3-" + this.fixedOutputLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public int doFinal(byte[] out, int outOff) {
        absorbBits(2, 2);
        return super.doFinal(out, outOff);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public int doFinal(byte[] out, int outOff, byte partialByte, int partialBits) {
        if (partialBits < 0 || partialBits > 7) {
            throw new IllegalArgumentException("'partialBits' must be in the range [0,7]");
        }
        int finalInput = (((1 << partialBits) - 1) & partialByte) | (2 << partialBits);
        int finalBits = partialBits + 2;
        if (finalBits >= 8) {
            absorb((byte) finalInput);
            finalBits -= 8;
            finalInput >>>= 8;
        }
        return super.doFinal(out, outOff, (byte) finalInput, finalBits);
    }
}
