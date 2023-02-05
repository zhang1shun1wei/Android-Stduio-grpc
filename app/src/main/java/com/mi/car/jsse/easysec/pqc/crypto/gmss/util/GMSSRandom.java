package com.mi.car.jsse.easysec.pqc.crypto.gmss.util;

import com.mi.car.jsse.easysec.crypto.Digest;

public class GMSSRandom {
    private Digest messDigestTree;

    public GMSSRandom(Digest messDigestTree2) {
        this.messDigestTree = messDigestTree2;
    }

    public byte[] nextSeed(byte[] outseed) {
        byte[] bArr = new byte[outseed.length];
        this.messDigestTree.update(outseed, 0, outseed.length);
        byte[] rand = new byte[this.messDigestTree.getDigestSize()];
        this.messDigestTree.doFinal(rand, 0);
        addByteArrays(outseed, rand);
        addOne(outseed);
        return rand;
    }

    private void addByteArrays(byte[] a, byte[] b) {
        byte overflow = 0;
        for (int i = 0; i < a.length; i++) {
            int temp = (a[i] & 255) + (b[i] & 255) + overflow;
            a[i] = (byte) temp;
            overflow = (byte) (temp >> 8);
        }
    }

    private void addOne(byte[] a) {
        byte overflow = 1;
        for (int i = 0; i < a.length; i++) {
            int temp = (a[i] & 255) + overflow;
            a[i] = (byte) temp;
            overflow = (byte) (temp >> 8);
        }
    }
}
