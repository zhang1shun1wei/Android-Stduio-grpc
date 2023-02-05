package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.util.Arrays;
import java.lang.reflect.Array;

public class Haraka256Digest extends HarakaBase {
    private static final byte[][] RC = {new byte[]{6, -124, 112, 76, -26, 32, -64, 10, -78, -59, -2, -16, 117, -127, 123, -99}, new byte[]{-117, 102, -76, -31, -120, -13, -96, 107, 100, 15, 107, -92, 47, 8, -9, 23}, new byte[]{52, 2, -34, 45, 83, -14, -124, -104, -49, 2, -99, 96, -97, 2, -111, 20}, new byte[]{14, -42, -22, -26, 46, 123, 79, 8, -69, -13, PSSSigner.TRAILER_IMPLICIT, -81, -3, 91, 79, 121}, new byte[]{-53, -49, -80, -53, 72, 114, 68, -117, 121, -18, -51, 28, -66, 57, 112, 68}, new byte[]{126, -22, -51, -18, 110, -112, 50, -73, -115, 83, 53, -19, 43, -118, 5, 123}, new byte[]{103, -62, -113, 67, 94, 46, 124, -48, -30, 65, 39, 97, -38, 79, -17, 27}, new byte[]{41, 36, -39, -80, -81, -54, -52, 7, 103, 95, -3, -30, 31, -57, 11, 59}, new byte[]{-85, 77, 99, -15, -26, -122, Byte.MAX_VALUE, -23, -20, -37, -113, -54, -71, -44, 101, -18}, new byte[]{28, 48, -65, -124, -44, -73, -51, 100, 91, 42, 64, 79, -83, 3, 126, 51}, new byte[]{-78, -52, 11, -71, -108, 23, 35, -65, 105, 2, -117, 46, -115, -10, -104, 0}, new byte[]{-6, 4, 120, -90, -34, 111, 85, 114, 74, -86, -98, -56, 92, -99, 45, -118}, new byte[]{-33, -76, -97, 43, 107, 119, 42, 18, 14, -6, 79, 46, 41, 18, -97, -44}, new byte[]{30, -95, 3, 68, -12, 73, -94, 54, 50, -42, 17, -82, -69, 106, 18, -18}, new byte[]{-81, 4, 73, -120, 75, 5, 0, -124, 95, -106, 0, -55, -100, -88, -20, -90}, new byte[]{33, 2, 94, -40, -99, 25, -100, 79, 120, -94, -57, -29, 39, -27, -109, -20}, new byte[]{-65, 58, -86, -8, -89, 89, -55, -73, -71, 40, 46, -51, -126, -44, 1, 115}, new byte[]{98, 96, 112, 13, 97, -122, -80, 23, 55, -14, -17, -39, Tnaf.POW_2_WIDTH, 48, 125, 107}, new byte[]{90, -54, 69, -62, 33, 48, 4, 67, -127, -62, -111, 83, -10, -4, -102, -58}, new byte[]{-110, 35, -105, 60, 34, 107, 104, -69, 44, -81, -110, -24, 54, -47, -108, 58}};
    private final byte[] buffer;
    private int off;

    private void mix256(byte[][] s1, byte[][] s2) {
        System.arraycopy(s1[0], 0, s2[0], 0, 4);
        System.arraycopy(s1[1], 0, s2[0], 4, 4);
        System.arraycopy(s1[0], 4, s2[0], 8, 4);
        System.arraycopy(s1[1], 4, s2[0], 12, 4);
        System.arraycopy(s1[0], 8, s2[1], 0, 4);
        System.arraycopy(s1[1], 8, s2[1], 4, 4);
        System.arraycopy(s1[0], 12, s2[1], 8, 4);
        System.arraycopy(s1[1], 12, s2[1], 12, 4);
    }

    private int haraka256256(byte[] msg, byte[] out, int outOff) {
        byte[][] s1 = (byte[][]) Array.newInstance(Byte.TYPE, 2, 16);
        byte[][] s2 = (byte[][]) Array.newInstance(Byte.TYPE, 2, 16);
        System.arraycopy(msg, 0, s1[0], 0, 16);
        System.arraycopy(msg, 16, s1[1], 0, 16);
        s1[0] = aesEnc(s1[0], RC[0]);
        s1[1] = aesEnc(s1[1], RC[1]);
        s1[0] = aesEnc(s1[0], RC[2]);
        s1[1] = aesEnc(s1[1], RC[3]);
        mix256(s1, s2);
        s1[0] = aesEnc(s2[0], RC[4]);
        s1[1] = aesEnc(s2[1], RC[5]);
        s1[0] = aesEnc(s1[0], RC[6]);
        s1[1] = aesEnc(s1[1], RC[7]);
        mix256(s1, s2);
        s1[0] = aesEnc(s2[0], RC[8]);
        s1[1] = aesEnc(s2[1], RC[9]);
        s1[0] = aesEnc(s1[0], RC[10]);
        s1[1] = aesEnc(s1[1], RC[11]);
        mix256(s1, s2);
        s1[0] = aesEnc(s2[0], RC[12]);
        s1[1] = aesEnc(s2[1], RC[13]);
        s1[0] = aesEnc(s1[0], RC[14]);
        s1[1] = aesEnc(s1[1], RC[15]);
        mix256(s1, s2);
        s1[0] = aesEnc(s2[0], RC[16]);
        s1[1] = aesEnc(s2[1], RC[17]);
        s1[0] = aesEnc(s1[0], RC[18]);
        s1[1] = aesEnc(s1[1], RC[19]);
        mix256(s1, s2);
        s1[0] = xor(s2[0], msg, 0);
        s1[1] = xor(s2[1], msg, 16);
        System.arraycopy(s1[0], 0, out, outOff, 16);
        System.arraycopy(s1[1], 0, out, outOff + 16, 16);
        return 32;
    }

    public Haraka256Digest() {
        this.buffer = new byte[32];
    }

    public Haraka256Digest(Haraka256Digest digest) {
        this.buffer = Arrays.clone(digest.buffer);
        this.off = digest.off;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "Haraka-256";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        if (this.off + 1 > 32) {
            throw new IllegalArgumentException("total input cannot be more than 32 bytes");
        }
        byte[] bArr = this.buffer;
        int i = this.off;
        this.off = i + 1;
        bArr[i] = in;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        if (this.off + len > 32) {
            throw new IllegalArgumentException("total input cannot be more than 32 bytes");
        }
        System.arraycopy(in, inOff, this.buffer, this.off, len);
        this.off += len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        if (this.off != 32) {
            throw new IllegalStateException("input must be exactly 32 bytes");
        } else if (out.length - outOff < 32) {
            throw new IllegalArgumentException("output too short to receive digest");
        } else {
            int rv = haraka256256(this.buffer, out, outOff);
            reset();
            return rv;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.off = 0;
        Arrays.clear(this.buffer);
    }
}
