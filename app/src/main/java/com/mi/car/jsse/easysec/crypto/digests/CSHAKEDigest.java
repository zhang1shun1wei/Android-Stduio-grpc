package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.util.Arrays;

public class CSHAKEDigest extends SHAKEDigest {
    private static final byte[] padding = new byte[100];
    private final byte[] diff;

    public CSHAKEDigest(int bitLength, byte[] N, byte[] S) {
        super(bitLength);
        if ((N == null || N.length == 0) && (S == null || S.length == 0)) {
            this.diff = null;
            return;
        }
        this.diff = Arrays.concatenate(XofUtils.leftEncode((long) (this.rate / 8)), encodeString(N), encodeString(S));
        diffPadAndAbsorb();
    }

    CSHAKEDigest(CSHAKEDigest source) {
        super(source);
        this.diff = Arrays.clone(source.diff);
    }

    private void diffPadAndAbsorb() {
        int blockSize = this.rate / 8;
        absorb(this.diff, 0, this.diff.length);
        int delta = this.diff.length % blockSize;
        if (delta != 0) {
            int required = blockSize - delta;
            while (required > padding.length) {
                absorb(padding, 0, padding.length);
                required -= padding.length;
            }
            absorb(padding, 0, required);
        }
    }

    private byte[] encodeString(byte[] str) {
        if (str == null || str.length == 0) {
            return XofUtils.leftEncode(0);
        }
        return Arrays.concatenate(XofUtils.leftEncode(((long) str.length) * 8), str);
    }

    @Override // com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest, com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public String getAlgorithmName() {
        return "CSHAKE" + this.fixedOutputLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest, com.mi.car.jsse.easysec.crypto.Xof
    public int doOutput(byte[] out, int outOff, int outLen) {
        if (this.diff == null) {
            return super.doOutput(out, outOff, outLen);
        }
        if (!this.squeezing) {
            absorbBits(0, 2);
        }
        squeeze(out, outOff, ((long) outLen) * 8);
        return outLen;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.KeccakDigest
    public void reset() {
        super.reset();
        if (this.diff != null) {
            diffPadAndAbsorb();
        }
    }
}
