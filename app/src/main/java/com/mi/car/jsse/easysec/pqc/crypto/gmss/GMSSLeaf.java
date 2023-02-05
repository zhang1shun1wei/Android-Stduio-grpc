package com.mi.car.jsse.easysec.pqc.crypto.gmss;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.GMSSRandom;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;

public class GMSSLeaf {
    private byte[] concHashs;
    private GMSSRandom gmssRandom;
    private int i;
    private int j;
    private int keysize;
    private byte[] leaf;
    private int mdsize;
    private Digest messDigestOTS;
    byte[] privateKeyOTS;
    private byte[] seed;
    private int steps;
    private int two_power_w;
    private int w;

    public GMSSLeaf(Digest digest, byte[][] otsIndex, int[] numLeafs) {
        this.i = numLeafs[0];
        this.j = numLeafs[1];
        this.steps = numLeafs[2];
        this.w = numLeafs[3];
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int messagesize = (int) Math.ceil(((double) (this.mdsize << 3)) / ((double) this.w));
        this.keysize = ((int) Math.ceil(((double) getLog((messagesize << this.w) + 1)) / ((double) this.w))) + messagesize;
        this.two_power_w = 1 << this.w;
        this.privateKeyOTS = otsIndex[0];
        this.seed = otsIndex[1];
        this.concHashs = otsIndex[2];
        this.leaf = otsIndex[3];
    }

    GMSSLeaf(Digest digest, int w2, int numLeafs) {
        this.w = w2;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int messagesize = (int) Math.ceil(((double) (this.mdsize << 3)) / ((double) w2));
        this.keysize = ((int) Math.ceil(((double) getLog((messagesize << w2) + 1)) / ((double) w2))) + messagesize;
        this.two_power_w = 1 << w2;
        this.steps = (int) Math.ceil(((double) (((((1 << w2) - 1) * this.keysize) + 1) + this.keysize)) / ((double) numLeafs));
        this.seed = new byte[this.mdsize];
        this.leaf = new byte[this.mdsize];
        this.privateKeyOTS = new byte[this.mdsize];
        this.concHashs = new byte[(this.mdsize * this.keysize)];
    }

    public GMSSLeaf(Digest digest, int w2, int numLeafs, byte[] seed0) {
        this.w = w2;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int messagesize = (int) Math.ceil(((double) (this.mdsize << 3)) / ((double) w2));
        this.keysize = ((int) Math.ceil(((double) getLog((messagesize << w2) + 1)) / ((double) w2))) + messagesize;
        this.two_power_w = 1 << w2;
        this.steps = (int) Math.ceil(((double) (((((1 << w2) - 1) * this.keysize) + 1) + this.keysize)) / ((double) numLeafs));
        this.seed = new byte[this.mdsize];
        this.leaf = new byte[this.mdsize];
        this.privateKeyOTS = new byte[this.mdsize];
        this.concHashs = new byte[(this.mdsize * this.keysize)];
        initLeafCalc(seed0);
    }

    private GMSSLeaf(GMSSLeaf original) {
        this.messDigestOTS = original.messDigestOTS;
        this.mdsize = original.mdsize;
        this.keysize = original.keysize;
        this.gmssRandom = original.gmssRandom;
        this.leaf = Arrays.clone(original.leaf);
        this.concHashs = Arrays.clone(original.concHashs);
        this.i = original.i;
        this.j = original.j;
        this.two_power_w = original.two_power_w;
        this.w = original.w;
        this.steps = original.steps;
        this.seed = Arrays.clone(original.seed);
        this.privateKeyOTS = Arrays.clone(original.privateKeyOTS);
    }

    /* access modifiers changed from: package-private */
    public void initLeafCalc(byte[] seed0) {
        this.i = 0;
        this.j = 0;
        byte[] dummy = new byte[this.mdsize];
        System.arraycopy(seed0, 0, dummy, 0, this.seed.length);
        this.seed = this.gmssRandom.nextSeed(dummy);
    }

    /* access modifiers changed from: package-private */
    public GMSSLeaf nextLeaf() {
        GMSSLeaf nextLeaf = new GMSSLeaf(this);
        nextLeaf.updateLeafCalc();
        return nextLeaf;
    }

    private void updateLeafCalc() {
        byte[] buf = new byte[this.messDigestOTS.getDigestSize()];
        for (int s = 0; s < this.steps + 10000; s++) {
            if (this.i == this.keysize && this.j == this.two_power_w - 1) {
                this.messDigestOTS.update(this.concHashs, 0, this.concHashs.length);
                this.leaf = new byte[this.messDigestOTS.getDigestSize()];
                this.messDigestOTS.doFinal(this.leaf, 0);
                return;
            }
            if (this.i == 0 || this.j == this.two_power_w - 1) {
                this.i++;
                this.j = 0;
                this.privateKeyOTS = this.gmssRandom.nextSeed(this.seed);
            } else {
                this.messDigestOTS.update(this.privateKeyOTS, 0, this.privateKeyOTS.length);
                this.privateKeyOTS = buf;
                this.messDigestOTS.doFinal(this.privateKeyOTS, 0);
                this.j++;
                if (this.j == this.two_power_w - 1) {
                    System.arraycopy(this.privateKeyOTS, 0, this.concHashs, this.mdsize * (this.i - 1), this.mdsize);
                }
            }
        }
        throw new IllegalStateException("unable to updateLeaf in steps: " + this.steps + " " + this.i + " " + this.j);
    }

    public byte[] getLeaf() {
        return Arrays.clone(this.leaf);
    }

    private int getLog(int intValue) {
        int log = 1;
        int i2 = 2;
        while (i2 < intValue) {
            i2 <<= 1;
            log++;
        }
        return log;
    }

    public byte[][] getStatByte() {
        return new byte[][]{this.privateKeyOTS, this.seed, this.concHashs, this.leaf};
    }

    public int[] getStatInt() {
        return new int[]{this.i, this.j, this.steps, this.w};
    }

    public String toString() {
        String out = "";
        for (int i2 = 0; i2 < 4; i2++) {
            out = out + getStatInt()[i2] + " ";
        }
        String out2 = out + " " + this.mdsize + " " + this.keysize + " " + this.two_power_w + " ";
        byte[][] temp = getStatByte();
        for (int i3 = 0; i3 < 4; i3++) {
            out2 = temp[i3] != null ? out2 + new String(Hex.encode(temp[i3])) + " " : out2 + "null ";
        }
        return out2;
    }
}
