package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

class WotsPlus {
    private final SPHINCSPlusEngine engine;
    private final int w;

    WotsPlus(SPHINCSPlusEngine engine) {
        this.engine = engine;
        this.w = this.engine.WOTS_W;
    }

    byte[] pkGen(byte[] skSeed, byte[] pkSeed, ADRS paramAdrs) {
        ADRS wotspkADRS = new ADRS(paramAdrs);
        byte[][] tmp = new byte[this.engine.WOTS_LEN][];

        for(int i = 0; i < this.engine.WOTS_LEN; ++i) {
            ADRS adrs = new ADRS(paramAdrs);
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            byte[] sk = this.engine.PRF(pkSeed, skSeed, adrs);
            tmp[i] = this.chain(sk, 0, this.w - 1, pkSeed, adrs);
        }

        wotspkADRS.setType(1);
        wotspkADRS.setKeyPairAddress(paramAdrs.getKeyPairAddress());
        return this.engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }

    byte[] chain(byte[] X, int i, int s, byte[] pkSeed, ADRS adrs) {
        if (s == 0) {
            return Arrays.clone(X);
        } else if (i + s > this.w - 1) {
            return null;
        } else {
            byte[] tmp = this.chain(X, i, s - 1, pkSeed, adrs);
            adrs.setHashAddress(i + s - 1);
            tmp = this.engine.F(pkSeed, adrs, tmp);
            return tmp;
        }
    }

    public byte[] sign(byte[] M, byte[] skSeed, byte[] pkSeed, ADRS paramAdrs) {
        ADRS adrs = new ADRS(paramAdrs);
        int csum = 0;
        int[] msg = this.base_w(M, this.w, this.engine.WOTS_LEN1);

        int len_2_bytes;
        for(len_2_bytes = 0; len_2_bytes < this.engine.WOTS_LEN1; ++len_2_bytes) {
            csum += this.w - 1 - msg[len_2_bytes];
        }

        if (this.engine.WOTS_LOGW % 8 != 0) {
            csum <<= 8 - this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW % 8;
        }

        len_2_bytes = (this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW + 7) / 8;
        byte[] bytes = Pack.intToBigEndian(csum);
        msg = Arrays.concatenate(msg, this.base_w(Arrays.copyOfRange(bytes, len_2_bytes, bytes.length), this.w, this.engine.WOTS_LEN2));
        byte[][] sig = new byte[this.engine.WOTS_LEN][];

        for(int i = 0; i < this.engine.WOTS_LEN; ++i) {
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            byte[] sk = this.engine.PRF(pkSeed, skSeed, adrs);
            sig[i] = this.chain(sk, 0, msg[i], pkSeed, adrs);
        }

        return Arrays.concatenate(sig);
    }

    int[] base_w(byte[] X, int w, int out_len) {
        int in = 0;
        int out = 0;
        int total = 0;
        int bits = 0;
        int[] output = new int[out_len];

        for(int consumed = 0; consumed < out_len; ++consumed) {
            if (bits == 0) {
                total = X[in];
                ++in;
                bits += 8;
            }

            bits -= this.engine.WOTS_LOGW;
            output[out] = total >>> bits & w - 1;
            ++out;
        }

        return output;
    }

    public byte[] pkFromSig(byte[] sig, byte[] M, byte[] pkSeed, ADRS adrs) {
        int csum = 0;
        ADRS wotspkADRS = new ADRS(adrs);
        int[] msg = this.base_w(M, this.w, this.engine.WOTS_LEN1);

        int len_2_bytes;
        for(len_2_bytes = 0; len_2_bytes < this.engine.WOTS_LEN1; ++len_2_bytes) {
            csum += this.w - 1 - msg[len_2_bytes];
        }

        csum <<= 8 - this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW % 8;
        len_2_bytes = (this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW + 7) / 8;
        msg = Arrays.concatenate(msg, this.base_w(Arrays.copyOfRange(Pack.intToBigEndian(csum), 4 - len_2_bytes, 4), this.w, this.engine.WOTS_LEN2));
        byte[] sigI = new byte[this.engine.N];
        byte[][] tmp = new byte[this.engine.WOTS_LEN][];

        for(int i = 0; i < this.engine.WOTS_LEN; ++i) {
            adrs.setChainAddress(i);
            System.arraycopy(sig, i * this.engine.N, sigI, 0, this.engine.N);
            tmp[i] = this.chain(sigI, msg[i], this.w - 1 - msg[i], pkSeed, adrs);
        }

        wotspkADRS.setType(1);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        return this.engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }
}
