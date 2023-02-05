package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.crypto.params.SkeinParameters;
import com.mi.car.jsse.easysec.util.Memoable;

public class SkeinDigest implements ExtendedDigest, Memoable {
    public static final int SKEIN_1024 = 1024;
    public static final int SKEIN_256 = 256;
    public static final int SKEIN_512 = 512;
    private SkeinEngine engine;

    public SkeinDigest(int stateSizeBits, int digestSizeBits) {
        this.engine = new SkeinEngine(stateSizeBits, digestSizeBits);
        init(null);
    }

    public SkeinDigest(SkeinDigest digest) {
        this.engine = new SkeinEngine(digest.engine);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public void reset(Memoable other) {
        this.engine.reset(((SkeinDigest) other).engine);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public Memoable copy() {
        return new SkeinDigest(this);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "Skein-" + (this.engine.getBlockSize() * 8) + "-" + (this.engine.getOutputSize() * 8);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.engine.getOutputSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return this.engine.getBlockSize();
    }

    public void init(SkeinParameters params) {
        this.engine.init(params);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.engine.reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        this.engine.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        this.engine.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        return this.engine.doFinal(out, outOff);
    }
}
