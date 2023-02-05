package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StatelessProcessing;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;

public class CamelliaLightEngine implements BlockCipher, StatelessProcessing {
    private static final int BLOCK_SIZE = 16;
    private static final int MASK8 = 255;
    private static final byte[] SBOX1 = {112, -126, 44, -20, -77, 39, -64, -27, -28, -123, 87, 53, -22, 12, -82, 65, 35, -17, 107, -109, 69, 25, -91, 33, -19, 14, 79, 78, 29, 101, -110, -67, -122, -72, -81, -113, 124, -21, 31, -50, 62, 48, -36, 95, 94, -59, 11, 26, -90, -31, 57, -54, -43, 71, 93, 61, -39, 1, 90, -42, 81, 86, 108, 77, -117, 13, -102, 102, -5, -52, -80, 45, 116, 18, 43, 32, -16, -79, -124, -103, -33, 76, -53, -62, 52, 126, 118, 5, 109, -73, -87, 49, -47, 23, 4, -41, 20, 88, 58, 97, -34, 27, 17, 28, 50, 15, -100, 22, 83, 24, -14, 34, -2, 68, -49, -78, -61, -75, 122, -111, 36, 8, -24, -88, 96, -4, 105, 80, -86, -48, -96, 125, -95, -119, 98, -105, 84, 91, 30, -107, -32, -1, 100, -46, Tnaf.POW_2_WIDTH, -60, 0, 72, -93, -9, 117, -37, -118, 3, -26, -38, 9, 63, -35, -108, -121, 92, -125, 2, -51, 74, -112, 51, 115, 103, -10, -13, -99, Byte.MAX_VALUE, -65, -30, 82, -101, -40, 38, -56, 55, -58, 59, -127, -106, 111, 75, 19, -66, 99, 46, -23, 121, -89, -116, -97, 110, PSSSigner.TRAILER_IMPLICIT, -114, 41, -11, -7, -74, 47, -3, -76, 89, 120, -104, 6, 106, -25, 70, 113, -70, -44, 37, -85, 66, -120, -94, -115, -6, 114, 7, -71, 85, -8, -18, -84, 10, 54, 73, 42, 104, 60, 56, -15, -92, 64, 40, -45, 123, -69, -55, 67, -63, 21, -29, -83, -12, 119, -57, Byte.MIN_VALUE, -98};
    private static final int[] SIGMA = {-1600231809, 1003262091, -1233459112, 1286239154, -957401297, -380665154, 1426019237, -237801700, 283453434, -563598051, -1336506174, -1276722691};
    private boolean _keyis128;
    private boolean initialized;
    private int[] ke = new int[12];
    private int[] kw = new int[8];
    private int[] subkey = new int[96];

    private static int rightRotate(int x, int s) {
        return (x >>> s) + (x << (32 - s));
    }

    private static int leftRotate(int x, int s) {
        return (x << s) + (x >>> (32 - s));
    }

    private static void roldq(int rot, int[] ki, int ioff, int[] ko, int ooff) {
        ko[ooff + 0] = (ki[ioff + 0] << rot) | (ki[ioff + 1] >>> (32 - rot));
        ko[ooff + 1] = (ki[ioff + 1] << rot) | (ki[ioff + 2] >>> (32 - rot));
        ko[ooff + 2] = (ki[ioff + 2] << rot) | (ki[ioff + 3] >>> (32 - rot));
        ko[ooff + 3] = (ki[ioff + 3] << rot) | (ki[ioff + 0] >>> (32 - rot));
        ki[ioff + 0] = ko[ooff + 0];
        ki[ioff + 1] = ko[ooff + 1];
        ki[ioff + 2] = ko[ooff + 2];
        ki[ioff + 3] = ko[ooff + 3];
    }

    private static void decroldq(int rot, int[] ki, int ioff, int[] ko, int ooff) {
        ko[ooff + 2] = (ki[ioff + 0] << rot) | (ki[ioff + 1] >>> (32 - rot));
        ko[ooff + 3] = (ki[ioff + 1] << rot) | (ki[ioff + 2] >>> (32 - rot));
        ko[ooff + 0] = (ki[ioff + 2] << rot) | (ki[ioff + 3] >>> (32 - rot));
        ko[ooff + 1] = (ki[ioff + 3] << rot) | (ki[ioff + 0] >>> (32 - rot));
        ki[ioff + 0] = ko[ooff + 2];
        ki[ioff + 1] = ko[ooff + 3];
        ki[ioff + 2] = ko[ooff + 0];
        ki[ioff + 3] = ko[ooff + 1];
    }

    private static void roldqo32(int rot, int[] ki, int ioff, int[] ko, int ooff) {
        ko[ooff + 0] = (ki[ioff + 1] << (rot - 32)) | (ki[ioff + 2] >>> (64 - rot));
        ko[ooff + 1] = (ki[ioff + 2] << (rot - 32)) | (ki[ioff + 3] >>> (64 - rot));
        ko[ooff + 2] = (ki[ioff + 3] << (rot - 32)) | (ki[ioff + 0] >>> (64 - rot));
        ko[ooff + 3] = (ki[ioff + 0] << (rot - 32)) | (ki[ioff + 1] >>> (64 - rot));
        ki[ioff + 0] = ko[ooff + 0];
        ki[ioff + 1] = ko[ooff + 1];
        ki[ioff + 2] = ko[ooff + 2];
        ki[ioff + 3] = ko[ooff + 3];
    }

    private static void decroldqo32(int rot, int[] ki, int ioff, int[] ko, int ooff) {
        ko[ooff + 2] = (ki[ioff + 1] << (rot - 32)) | (ki[ioff + 2] >>> (64 - rot));
        ko[ooff + 3] = (ki[ioff + 2] << (rot - 32)) | (ki[ioff + 3] >>> (64 - rot));
        ko[ooff + 0] = (ki[ioff + 3] << (rot - 32)) | (ki[ioff + 0] >>> (64 - rot));
        ko[ooff + 1] = (ki[ioff + 0] << (rot - 32)) | (ki[ioff + 1] >>> (64 - rot));
        ki[ioff + 0] = ko[ooff + 2];
        ki[ioff + 1] = ko[ooff + 3];
        ki[ioff + 2] = ko[ooff + 0];
        ki[ioff + 3] = ko[ooff + 1];
    }

    private int bytes2int(byte[] src, int offset) {
        int word = 0;
        for (int i = 0; i < 4; i++) {
            word = (word << 8) + (src[i + offset] & 255);
        }
        return word;
    }

    private void int2bytes(int word, byte[] dst, int offset) {
        for (int i = 0; i < 4; i++) {
            dst[(3 - i) + offset] = (byte) word;
            word >>>= 8;
        }
    }

    private byte lRot8(byte v, int rot) {
        return (byte) ((v << rot) | ((v & 255) >>> (8 - rot)));
    }

    private int sbox2(int x) {
        return lRot8(SBOX1[x], 1) & 255;
    }

    private int sbox3(int x) {
        return lRot8(SBOX1[x], 7) & 255;
    }

    private int sbox4(int x) {
        return SBOX1[lRot8((byte) x, 1) & 255] & 255;
    }

    private void camelliaF2(int[] s, int[] skey, int keyoff) {
        int t1 = s[0] ^ skey[keyoff + 0];
        int u = sbox4(t1 & 255) | (sbox3((t1 >>> 8) & 255) << 8) | (sbox2((t1 >>> 16) & 255) << 16) | ((SBOX1[(t1 >>> 24) & 255] & 255) << 24);
        int t2 = s[1] ^ skey[keyoff + 1];
        int v = leftRotate((SBOX1[t2 & 255] & 255) | (sbox4((t2 >>> 8) & 255) << 8) | (sbox3((t2 >>> 16) & 255) << 16) | (sbox2((t2 >>> 24) & 255) << 24), 8);
        int u2 = u ^ v;
        int v2 = leftRotate(v, 8) ^ u2;
        int u3 = rightRotate(u2, 8) ^ v2;
        s[2] = s[2] ^ (leftRotate(v2, 16) ^ u3);
        s[3] = s[3] ^ leftRotate(u3, 8);
        int t12 = s[2] ^ skey[keyoff + 2];
        int u4 = sbox4(t12 & 255) | (sbox3((t12 >>> 8) & 255) << 8) | (sbox2((t12 >>> 16) & 255) << 16) | ((SBOX1[(t12 >>> 24) & 255] & 255) << 24);
        int t22 = s[3] ^ skey[keyoff + 3];
        int v3 = leftRotate((SBOX1[t22 & 255] & 255) | (sbox4((t22 >>> 8) & 255) << 8) | (sbox3((t22 >>> 16) & 255) << 16) | (sbox2((t22 >>> 24) & 255) << 24), 8);
        int u5 = u4 ^ v3;
        int v4 = leftRotate(v3, 8) ^ u5;
        int u6 = rightRotate(u5, 8) ^ v4;
        s[0] = s[0] ^ (leftRotate(v4, 16) ^ u6);
        s[1] = s[1] ^ leftRotate(u6, 8);
    }

    private void camelliaFLs(int[] s, int[] fkey, int keyoff) {
        s[1] = s[1] ^ leftRotate(s[0] & fkey[keyoff + 0], 1);
        s[0] = s[0] ^ (fkey[keyoff + 1] | s[1]);
        s[2] = s[2] ^ (fkey[keyoff + 3] | s[3]);
        s[3] = s[3] ^ leftRotate(fkey[keyoff + 2] & s[2], 1);
    }

    private void setKey(boolean forEncryption, byte[] key) {
        int[] k = new int[8];
        int[] ka = new int[4];
        int[] kb = new int[4];
        int[] t = new int[4];
        switch (key.length) {
            case 16:
                this._keyis128 = true;
                k[0] = bytes2int(key, 0);
                k[1] = bytes2int(key, 4);
                k[2] = bytes2int(key, 8);
                k[3] = bytes2int(key, 12);
                k[7] = 0;
                k[6] = 0;
                k[5] = 0;
                k[4] = 0;
                break;
            case 24:
                k[0] = bytes2int(key, 0);
                k[1] = bytes2int(key, 4);
                k[2] = bytes2int(key, 8);
                k[3] = bytes2int(key, 12);
                k[4] = bytes2int(key, 16);
                k[5] = bytes2int(key, 20);
                k[6] = k[4] ^ -1;
                k[7] = k[5] ^ -1;
                this._keyis128 = false;
                break;
            case 32:
                k[0] = bytes2int(key, 0);
                k[1] = bytes2int(key, 4);
                k[2] = bytes2int(key, 8);
                k[3] = bytes2int(key, 12);
                k[4] = bytes2int(key, 16);
                k[5] = bytes2int(key, 20);
                k[6] = bytes2int(key, 24);
                k[7] = bytes2int(key, 28);
                this._keyis128 = false;
                break;
            default:
                throw new IllegalArgumentException("key sizes are only 16/24/32 bytes.");
        }
        for (int i = 0; i < 4; i++) {
            ka[i] = k[i] ^ k[i + 4];
        }
        camelliaF2(ka, SIGMA, 0);
        for (int i2 = 0; i2 < 4; i2++) {
            ka[i2] = ka[i2] ^ k[i2];
        }
        camelliaF2(ka, SIGMA, 4);
        if (!this._keyis128) {
            for (int i3 = 0; i3 < 4; i3++) {
                kb[i3] = ka[i3] ^ k[i3 + 4];
            }
            camelliaF2(kb, SIGMA, 8);
            if (forEncryption) {
                this.kw[0] = k[0];
                this.kw[1] = k[1];
                this.kw[2] = k[2];
                this.kw[3] = k[3];
                roldqo32(45, k, 0, this.subkey, 16);
                roldq(15, k, 0, this.ke, 4);
                roldq(17, k, 0, this.subkey, 32);
                roldqo32(34, k, 0, this.subkey, 44);
                roldq(15, k, 4, this.subkey, 4);
                roldq(15, k, 4, this.ke, 0);
                roldq(30, k, 4, this.subkey, 24);
                roldqo32(34, k, 4, this.subkey, 36);
                roldq(15, ka, 0, this.subkey, 8);
                roldq(30, ka, 0, this.subkey, 20);
                this.ke[8] = ka[1];
                this.ke[9] = ka[2];
                this.ke[10] = ka[3];
                this.ke[11] = ka[0];
                roldqo32(49, ka, 0, this.subkey, 40);
                this.subkey[0] = kb[0];
                this.subkey[1] = kb[1];
                this.subkey[2] = kb[2];
                this.subkey[3] = kb[3];
                roldq(30, kb, 0, this.subkey, 12);
                roldq(30, kb, 0, this.subkey, 28);
                roldqo32(51, kb, 0, this.kw, 4);
                return;
            }
            this.kw[4] = k[0];
            this.kw[5] = k[1];
            this.kw[6] = k[2];
            this.kw[7] = k[3];
            decroldqo32(45, k, 0, this.subkey, 28);
            decroldq(15, k, 0, this.ke, 4);
            decroldq(17, k, 0, this.subkey, 12);
            decroldqo32(34, k, 0, this.subkey, 0);
            decroldq(15, k, 4, this.subkey, 40);
            decroldq(15, k, 4, this.ke, 8);
            decroldq(30, k, 4, this.subkey, 20);
            decroldqo32(34, k, 4, this.subkey, 8);
            decroldq(15, ka, 0, this.subkey, 36);
            decroldq(30, ka, 0, this.subkey, 24);
            this.ke[2] = ka[1];
            this.ke[3] = ka[2];
            this.ke[0] = ka[3];
            this.ke[1] = ka[0];
            decroldqo32(49, ka, 0, this.subkey, 4);
            this.subkey[46] = kb[0];
            this.subkey[47] = kb[1];
            this.subkey[44] = kb[2];
            this.subkey[45] = kb[3];
            decroldq(30, kb, 0, this.subkey, 32);
            decroldq(30, kb, 0, this.subkey, 16);
            roldqo32(51, kb, 0, this.kw, 0);
        } else if (forEncryption) {
            this.kw[0] = k[0];
            this.kw[1] = k[1];
            this.kw[2] = k[2];
            this.kw[3] = k[3];
            roldq(15, k, 0, this.subkey, 4);
            roldq(30, k, 0, this.subkey, 12);
            roldq(15, k, 0, t, 0);
            this.subkey[18] = t[2];
            this.subkey[19] = t[3];
            roldq(17, k, 0, this.ke, 4);
            roldq(17, k, 0, this.subkey, 24);
            roldq(17, k, 0, this.subkey, 32);
            this.subkey[0] = ka[0];
            this.subkey[1] = ka[1];
            this.subkey[2] = ka[2];
            this.subkey[3] = ka[3];
            roldq(15, ka, 0, this.subkey, 8);
            roldq(15, ka, 0, this.ke, 0);
            roldq(15, ka, 0, t, 0);
            this.subkey[16] = t[0];
            this.subkey[17] = t[1];
            roldq(15, ka, 0, this.subkey, 20);
            roldqo32(34, ka, 0, this.subkey, 28);
            roldq(17, ka, 0, this.kw, 4);
        } else {
            this.kw[4] = k[0];
            this.kw[5] = k[1];
            this.kw[6] = k[2];
            this.kw[7] = k[3];
            decroldq(15, k, 0, this.subkey, 28);
            decroldq(30, k, 0, this.subkey, 20);
            decroldq(15, k, 0, t, 0);
            this.subkey[16] = t[0];
            this.subkey[17] = t[1];
            decroldq(17, k, 0, this.ke, 0);
            decroldq(17, k, 0, this.subkey, 8);
            decroldq(17, k, 0, this.subkey, 0);
            this.subkey[34] = ka[0];
            this.subkey[35] = ka[1];
            this.subkey[32] = ka[2];
            this.subkey[33] = ka[3];
            decroldq(15, ka, 0, this.subkey, 24);
            decroldq(15, ka, 0, this.ke, 4);
            decroldq(15, ka, 0, t, 0);
            this.subkey[18] = t[2];
            this.subkey[19] = t[3];
            decroldq(15, ka, 0, this.subkey, 12);
            decroldqo32(34, ka, 0, this.subkey, 4);
            roldq(17, ka, 0, this.kw, 0);
        }
    }

    private int processBlock128(byte[] in, int inOff, byte[] out, int outOff) {
        int[] state = new int[4];
        for (int i = 0; i < 4; i++) {
            state[i] = bytes2int(in, (i * 4) + inOff) ^ this.kw[i];
        }
        camelliaF2(state, this.subkey, 0);
        camelliaF2(state, this.subkey, 4);
        camelliaF2(state, this.subkey, 8);
        camelliaFLs(state, this.ke, 0);
        camelliaF2(state, this.subkey, 12);
        camelliaF2(state, this.subkey, 16);
        camelliaF2(state, this.subkey, 20);
        camelliaFLs(state, this.ke, 4);
        camelliaF2(state, this.subkey, 24);
        camelliaF2(state, this.subkey, 28);
        camelliaF2(state, this.subkey, 32);
        state[2] = state[2] ^ this.kw[4];
        state[3] = state[3] ^ this.kw[5];
        state[0] = state[0] ^ this.kw[6];
        state[1] = state[1] ^ this.kw[7];
        int2bytes(state[2], out, outOff);
        int2bytes(state[3], out, outOff + 4);
        int2bytes(state[0], out, outOff + 8);
        int2bytes(state[1], out, outOff + 12);
        return 16;
    }

    private int processBlock192or256(byte[] in, int inOff, byte[] out, int outOff) {
        int[] state = new int[4];
        for (int i = 0; i < 4; i++) {
            state[i] = bytes2int(in, (i * 4) + inOff) ^ this.kw[i];
        }
        camelliaF2(state, this.subkey, 0);
        camelliaF2(state, this.subkey, 4);
        camelliaF2(state, this.subkey, 8);
        camelliaFLs(state, this.ke, 0);
        camelliaF2(state, this.subkey, 12);
        camelliaF2(state, this.subkey, 16);
        camelliaF2(state, this.subkey, 20);
        camelliaFLs(state, this.ke, 4);
        camelliaF2(state, this.subkey, 24);
        camelliaF2(state, this.subkey, 28);
        camelliaF2(state, this.subkey, 32);
        camelliaFLs(state, this.ke, 8);
        camelliaF2(state, this.subkey, 36);
        camelliaF2(state, this.subkey, 40);
        camelliaF2(state, this.subkey, 44);
        state[2] = state[2] ^ this.kw[4];
        state[3] = state[3] ^ this.kw[5];
        state[0] = state[0] ^ this.kw[6];
        state[1] = state[1] ^ this.kw[7];
        int2bytes(state[2], out, outOff);
        int2bytes(state[3], out, outOff + 4);
        int2bytes(state[0], out, outOff + 8);
        int2bytes(state[1], out, outOff + 12);
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Camellia";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption, CipherParameters params) {
        if (!(params instanceof KeyParameter)) {
            throw new IllegalArgumentException("only simple KeyParameter expected.");
        }
        setKey(forEncryption, ((KeyParameter) params).getKey());
        this.initialized = true;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Camellia is not initialized");
        } else if (inOff + 16 > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + 16 > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else if (this._keyis128) {
            return processBlock128(in, inOff, out, outOff);
        } else {
            return processBlock192or256(in, inOff, out, outOff);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    @Override // com.mi.car.jsse.easysec.crypto.StatelessProcessing
    public BlockCipher newInstance() {
        return new CamelliaLightEngine();
    }
}
