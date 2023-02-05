package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.util.Arrays;

public class Blake2xsDigest implements Xof {
    private static final int DIGEST_LENGTH = 32;
    private static final long MAX_NUMBER_BLOCKS = 4294967296L;
    public static final int UNKNOWN_DIGEST_LENGTH = 65535;
    private long blockPos;
    private byte[] buf;
    private int bufPos;
    private int digestLength;
    private int digestPos;
    private byte[] h0;
    private Blake2sDigest hash;
    private long nodeOffset;

    public Blake2xsDigest() {
        this((int) UNKNOWN_DIGEST_LENGTH);
    }

    public Blake2xsDigest(int digestBytes) {
        this(digestBytes, null, null, null);
    }

    public Blake2xsDigest(int digestBytes, byte[] key) {
        this(digestBytes, key, null, null);
    }

    public Blake2xsDigest(int digestBytes, byte[] key, byte[] salt, byte[] personalization) {
        this.h0 = null;
        this.buf = new byte[32];
        this.bufPos = 32;
        this.digestPos = 0;
        this.blockPos = 0;
        if (digestBytes < 1 || digestBytes > 65535) {
            throw new IllegalArgumentException("BLAKE2xs digest length must be between 1 and 2^16-1");
        }
        this.digestLength = digestBytes;
        this.nodeOffset = computeNodeOffset();
        this.hash = new Blake2sDigest(32, key, salt, personalization, this.nodeOffset);
    }

    public Blake2xsDigest(Blake2xsDigest digest) {
        this.h0 = null;
        this.buf = new byte[32];
        this.bufPos = 32;
        this.digestPos = 0;
        this.blockPos = 0;
        this.digestLength = digest.digestLength;
        this.hash = new Blake2sDigest(digest.hash);
        this.h0 = Arrays.clone(digest.h0);
        this.buf = Arrays.clone(digest.buf);
        this.bufPos = digest.bufPos;
        this.digestPos = digest.digestPos;
        this.blockPos = digest.blockPos;
        this.nodeOffset = digest.nodeOffset;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "BLAKE2xs";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.digestLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return this.hash.getByteLength();
    }

    public long getUnknownMaxLength() {
        return 137438953472L;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        this.hash.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        this.hash.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.hash.reset();
        this.h0 = null;
        this.bufPos = 32;
        this.digestPos = 0;
        this.blockPos = 0;
        this.nodeOffset = computeNodeOffset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOffset) {
        return doFinal(out, outOffset, out.length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doFinal(byte[] out, int outOff, int outLen) {
        int ret = doOutput(out, outOff, outLen);
        reset();
        return ret;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doOutput(byte[] out, int outOff, int outLen) {
        if (this.h0 == null) {
            this.h0 = new byte[this.hash.getDigestSize()];
            this.hash.doFinal(this.h0, 0);
        }
        if (this.digestLength != 65535) {
            if (this.digestPos + outLen > this.digestLength) {
                throw new IllegalArgumentException("Output length is above the digest length");
            }
        } else if ((this.blockPos << 5) >= getUnknownMaxLength()) {
            throw new IllegalArgumentException("Maximum length is 2^32 blocks of 32 bytes");
        }
        for (int i = 0; i < outLen; i++) {
            if (this.bufPos >= 32) {
                Blake2sDigest h = new Blake2sDigest(computeStepLength(), 32, this.nodeOffset);
                h.update(this.h0, 0, this.h0.length);
                Arrays.fill(this.buf, (byte) 0);
                h.doFinal(this.buf, 0);
                this.bufPos = 0;
                this.nodeOffset++;
                this.blockPos++;
            }
            out[i] = this.buf[this.bufPos];
            this.bufPos++;
            this.digestPos++;
        }
        return outLen;
    }

    private int computeStepLength() {
        if (this.digestLength == 65535) {
            return 32;
        }
        return Math.min(32, this.digestLength - this.digestPos);
    }

    private long computeNodeOffset() {
        return ((long) this.digestLength) * MAX_NUMBER_BLOCKS;
    }
}
