package com.mi.car.jsse.easysec.pqc.crypto.gmss.util;

import com.mi.car.jsse.easysec.crypto.Digest;

public class WinternitzOTSVerify {
    private int mdsize = this.messDigestOTS.getDigestSize();
    private Digest messDigestOTS;
    private int w;

    public WinternitzOTSVerify(Digest digest, int w2) {
        this.w = w2;
        this.messDigestOTS = digest;
    }

    public int getSignatureLength() {
        int mdsize2 = this.messDigestOTS.getDigestSize();
        int size = ((mdsize2 << 3) + (this.w - 1)) / this.w;
        return mdsize2 * (size + (((this.w + getLog((size << this.w) + 1)) - 1) / this.w));
    }

    public byte[] Verify(byte[] message, byte[] signature) {
        byte[] hash = new byte[this.mdsize];
        this.messDigestOTS.update(message, 0, message.length);
        this.messDigestOTS.doFinal(hash, 0);
        int size = ((this.mdsize << 3) + (this.w - 1)) / this.w;
        int logs = getLog((size << this.w) + 1);
        int testKeySize = this.mdsize * (size + (((this.w + logs) - 1) / this.w));
        if (testKeySize != signature.length) {
            return null;
        }
        byte[] testKey = new byte[testKeySize];
        int c = 0;
        int counter = 0;
        if (8 % this.w == 0) {
            int d = 8 / this.w;
            int k = (1 << this.w) - 1;
            for (int i = 0; i < hash.length; i++) {
                for (int j = 0; j < d; j++) {
                    int test = hash[i] & k;
                    c += test;
                    hashSignatureBlock(signature, counter * this.mdsize, k - test, testKey, counter * this.mdsize);
                    hash[i] = (byte) (hash[i] >>> this.w);
                    counter++;
                }
            }
            int c2 = (size << this.w) - c;
            int i2 = 0;
            while (i2 < logs) {
                hashSignatureBlock(signature, counter * this.mdsize, k - (c2 & k), testKey, counter * this.mdsize);
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
                    int test2 = (int) (((long) k2) & big8);
                    c += test2;
                    hashSignatureBlock(signature, counter * this.mdsize, k2 - test2, testKey, counter * this.mdsize);
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
                int test3 = (int) (((long) k2) & big82);
                c += test3;
                hashSignatureBlock(signature, counter * this.mdsize, k2 - test3, testKey, counter * this.mdsize);
                big82 >>>= this.w;
                counter++;
                j5 += this.w;
            }
            int c3 = (size << this.w) - c;
            int i4 = 0;
            while (i4 < logs) {
                hashSignatureBlock(signature, counter * this.mdsize, k2 - (c3 & k2), testKey, counter * this.mdsize);
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
                System.arraycopy(signature, this.mdsize * counter, hlp, 0, this.mdsize);
                while (test8 < ((long) k3)) {
                    this.messDigestOTS.update(hlp, 0, hlp.length);
                    this.messDigestOTS.doFinal(hlp, 0);
                    test8++;
                }
                System.arraycopy(hlp, 0, testKey, this.mdsize * counter, this.mdsize);
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
                System.arraycopy(signature, this.mdsize * counter, hlp, 0, this.mdsize);
                while (test82 < ((long) k3)) {
                    this.messDigestOTS.update(hlp, 0, hlp.length);
                    this.messDigestOTS.doFinal(hlp, 0);
                    test82++;
                }
                System.arraycopy(hlp, 0, testKey, this.mdsize * counter, this.mdsize);
                counter++;
            }
            int c4 = (size << this.w) - c;
            int i5 = 0;
            while (i5 < logs) {
                System.arraycopy(signature, this.mdsize * counter, hlp, 0, this.mdsize);
                for (long test83 = (long) (c4 & k3); test83 < ((long) k3); test83++) {
                    this.messDigestOTS.update(hlp, 0, hlp.length);
                    this.messDigestOTS.doFinal(hlp, 0);
                }
                System.arraycopy(hlp, 0, testKey, this.mdsize * counter, this.mdsize);
                c4 >>>= this.w;
                counter++;
                i5 += this.w;
            }
        }
        this.messDigestOTS.update(testKey, 0, testKey.length);
        byte[] TKey = new byte[this.mdsize];
        this.messDigestOTS.doFinal(TKey, 0);
        return TKey;
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

    private void hashSignatureBlock(byte[] sig, int sigOff, int rounds, byte[] buf, int bufOff) {
        if (rounds < 1) {
            System.arraycopy(sig, sigOff, buf, bufOff, this.mdsize);
            return;
        }
        this.messDigestOTS.update(sig, sigOff, this.mdsize);
        this.messDigestOTS.doFinal(buf, bufOff);
        while (true) {
            rounds--;
            if (rounds > 0) {
                this.messDigestOTS.update(buf, bufOff, this.mdsize);
                this.messDigestOTS.doFinal(buf, bufOff);
            } else {
                return;
            }
        }
    }
}
