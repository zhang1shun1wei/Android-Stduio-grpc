package com.mi.car.jsse.easysec.pqc.crypto.gmss.util;

import com.mi.car.jsse.easysec.crypto.Digest;

public class WinternitzOTSignature {
    private int checksumsize;
    private GMSSRandom gmssRandom = new GMSSRandom(this.messDigestOTS);
    private int keysize;
    private int mdsize = this.messDigestOTS.getDigestSize();
    private Digest messDigestOTS;
    private int messagesize;
    private byte[][] privateKeyOTS;
    private int w;

    public WinternitzOTSignature(byte[] seed0, Digest digest, int w2) {
        this.w = w2;
        this.messDigestOTS = digest;
        this.messagesize = (((this.mdsize << 3) + w2) - 1) / w2;
        this.checksumsize = getLog((this.messagesize << w2) + 1);
        this.keysize = this.messagesize + (((this.checksumsize + w2) - 1) / w2);
        this.privateKeyOTS = new byte[this.keysize][];
        byte[] dummy = new byte[this.mdsize];
        System.arraycopy(seed0, 0, dummy, 0, dummy.length);
        for (int i = 0; i < this.keysize; i++) {
            this.privateKeyOTS[i] = this.gmssRandom.nextSeed(dummy);
        }
    }

    public byte[][] getPrivateKey() {
        return this.privateKeyOTS;
    }

    public byte[] getPublicKey() {
        byte[] buf = new byte[(this.keysize * this.mdsize)];
        int pos = 0;
        int rounds = (1 << this.w) - 1;
        for (int i = 0; i < this.keysize; i++) {
            hashPrivateKeyBlock(i, rounds, buf, pos);
            pos += this.mdsize;
        }
        this.messDigestOTS.update(buf, 0, buf.length);
        byte[] tmp = new byte[this.mdsize];
        this.messDigestOTS.doFinal(tmp, 0);
        return tmp;
    }

    public byte[] getSignature(byte[] message) {
        byte[] sign = new byte[(this.keysize * this.mdsize)];
        byte[] hash = new byte[this.mdsize];
        int counter = 0;
        int c = 0;
        this.messDigestOTS.update(message, 0, message.length);
        this.messDigestOTS.doFinal(hash, 0);
        if (8 % this.w == 0) {
            int d = 8 / this.w;
            int k = (1 << this.w) - 1;
            for (int i = 0; i < hash.length; i++) {
                for (int j = 0; j < d; j++) {
                    int test = hash[i] & k;
                    c += test;
                    hashPrivateKeyBlock(counter, test, sign, this.mdsize * counter);
                    hash[i] = (byte) (hash[i] >>> this.w);
                    counter++;
                }
            }
            int c2 = (this.messagesize << this.w) - c;
            int i2 = 0;
            while (i2 < this.checksumsize) {
                hashPrivateKeyBlock(counter, c2 & k, sign, this.mdsize * counter);
                c2 >>>= this.w;
                counter++;
                i2 += this.w;
            }
        } else if (this.w < 8) {
            int d2 = this.mdsize / this.w;
            int k2 = (1 << this.w) - 1;
            int ii = 0;
            for (int i3 = 0; i3 < d2; i3++) {
                long big8 = 0;
                for (int j2 = 0; j2 < this.w; j2++) {
                    big8 ^= (long) ((hash[ii] & 255) << (j2 << 3));
                    ii++;
                }
                for (int j3 = 0; j3 < 8; j3++) {
                    int test2 = ((int) big8) & k2;
                    c += test2;
                    hashPrivateKeyBlock(counter, test2, sign, this.mdsize * counter);
                    big8 >>>= this.w;
                    counter++;
                }
            }
            int d3 = this.mdsize % this.w;
            long big82 = 0;
            for (int j4 = 0; j4 < d3; j4++) {
                big82 ^= (long) ((hash[ii] & 255) << (j4 << 3));
                ii++;
            }
            int d4 = d3 << 3;
            int j5 = 0;
            while (j5 < d4) {
                int test3 = ((int) big82) & k2;
                c += test3;
                hashPrivateKeyBlock(counter, test3, sign, this.mdsize * counter);
                big82 >>>= this.w;
                counter++;
                j5 += this.w;
            }
            int c3 = (this.messagesize << this.w) - c;
            int i4 = 0;
            while (i4 < this.checksumsize) {
                hashPrivateKeyBlock(counter, c3 & k2, sign, this.mdsize * counter);
                c3 >>>= this.w;
                counter++;
                i4 += this.w;
            }
        } else if (this.w < 57) {
            int d5 = (this.mdsize << 3) - this.w;
            int k3 = (1 << this.w) - 1;
            byte[] hlp = new byte[this.mdsize];
            int r = 0;
            while (r <= d5) {
                int s = r >>> 3;
                int rest = r % 8;
                r += this.w;
                int f = (r + 7) >>> 3;
                long big83 = 0;
                int ii2 = 0;
                for (int j6 = s; j6 < f; j6++) {
                    big83 ^= (long) ((hash[j6] & 255) << (ii2 << 3));
                    ii2++;
                }
                long test8 = (big83 >>> rest) & ((long) k3);
                c = (int) (((long) c) + test8);
                System.arraycopy(this.privateKeyOTS[counter], 0, hlp, 0, this.mdsize);
                while (test8 > 0) {
                    this.messDigestOTS.update(hlp, 0, hlp.length);
                    this.messDigestOTS.doFinal(hlp, 0);
                    test8--;
                }
                System.arraycopy(hlp, 0, sign, this.mdsize * counter, this.mdsize);
                counter++;
            }
            int s2 = r >>> 3;
            if (s2 < this.mdsize) {
                int rest2 = r % 8;
                long big84 = 0;
                int ii3 = 0;
                for (int j7 = s2; j7 < this.mdsize; j7++) {
                    big84 ^= (long) ((hash[j7] & 255) << (ii3 << 3));
                    ii3++;
                }
                long test82 = (big84 >>> rest2) & ((long) k3);
                c = (int) (((long) c) + test82);
                System.arraycopy(this.privateKeyOTS[counter], 0, hlp, 0, this.mdsize);
                while (test82 > 0) {
                    this.messDigestOTS.update(hlp, 0, hlp.length);
                    this.messDigestOTS.doFinal(hlp, 0);
                    test82--;
                }
                System.arraycopy(hlp, 0, sign, this.mdsize * counter, this.mdsize);
                counter++;
            }
            int c4 = (this.messagesize << this.w) - c;
            int i5 = 0;
            while (i5 < this.checksumsize) {
                System.arraycopy(this.privateKeyOTS[counter], 0, hlp, 0, this.mdsize);
                for (long test83 = (long) (c4 & k3); test83 > 0; test83--) {
                    this.messDigestOTS.update(hlp, 0, hlp.length);
                    this.messDigestOTS.doFinal(hlp, 0);
                }
                System.arraycopy(hlp, 0, sign, this.mdsize * counter, this.mdsize);
                c4 >>>= this.w;
                counter++;
                i5 += this.w;
            }
        }
        return sign;
    }

    public int getLog(int intValue) {
        int log = 1;
        int i = 2;
        while (i < intValue) {
            i <<= 1;
            log++;
        }
        return log;
    }

    private void hashPrivateKeyBlock(int index, int rounds, byte[] buf, int off) {
        if (rounds < 1) {
            System.arraycopy(this.privateKeyOTS[index], 0, buf, off, this.mdsize);
            return;
        }
        this.messDigestOTS.update(this.privateKeyOTS[index], 0, this.mdsize);
        this.messDigestOTS.doFinal(buf, off);
        while (true) {
            rounds--;
            if (rounds > 0) {
                this.messDigestOTS.update(buf, off, this.mdsize);
                this.messDigestOTS.doFinal(buf, off);
            } else {
                return;
            }
        }
    }
}
