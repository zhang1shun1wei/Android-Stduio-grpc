package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.Digest;

/* access modifiers changed from: package-private */
public class SeedDerive {
    private final byte[] I;
    private final Digest digest;
    private int j;
    private final byte[] masterSeed;
    private int q;

    public SeedDerive(byte[] I2, byte[] masterSeed2, Digest digest2) {
        this.I = I2;
        this.masterSeed = masterSeed2;
        this.digest = digest2;
    }

    public int getQ() {
        return this.q;
    }

    public void setQ(int q2) {
        this.q = q2;
    }

    public int getJ() {
        return this.j;
    }

    public void setJ(int j2) {
        this.j = j2;
    }

    public byte[] getI() {
        return this.I;
    }

    public byte[] getMasterSeed() {
        return this.masterSeed;
    }

    public byte[] deriveSeed(byte[] target, int offset) {
        if (target.length < this.digest.getDigestSize()) {
            throw new IllegalArgumentException("target length is less than digest size.");
        }
        this.digest.update(this.I, 0, this.I.length);
        this.digest.update((byte) (this.q >>> 24));
        this.digest.update((byte) (this.q >>> 16));
        this.digest.update((byte) (this.q >>> 8));
        this.digest.update((byte) this.q);
        this.digest.update((byte) (this.j >>> 8));
        this.digest.update((byte) this.j);
        this.digest.update((byte) -1);
        this.digest.update(this.masterSeed, 0, this.masterSeed.length);
        this.digest.doFinal(target, offset);
        return target;
    }

    public void deriveSeed(byte[] target, boolean incJ) {
        deriveSeed(target, incJ, 0);
    }

    public void deriveSeed(byte[] target, boolean incJ, int offset) {
        deriveSeed(target, offset);
        if (incJ) {
            this.j++;
        }
    }
}
