package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.crypto.StreamCipher;
import com.mi.car.jsse.easysec.crypto.engines.ChaChaEngine;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.Tree;
import com.mi.car.jsse.easysec.util.Pack;

class Seed {
    Seed() {
    }

    static void get_seed(HashFunctions hs, byte[] seed, int seedOff, byte[] sk, Tree.leafaddr a) {
        byte[] buffer = new byte[40];
        for (int i = 0; i < 32; i++) {
            buffer[i] = sk[i];
        }
        Pack.longToLittleEndian(((long) a.level) | (a.subtree << 4) | (a.subleaf << 59), buffer, 32);
        hs.varlen_hash(seed, seedOff, buffer, buffer.length);
    }

    static void prg(byte[] r, int rOff, long rlen, byte[] key, int keyOff) {
        StreamCipher cipher = new ChaChaEngine(12);
        cipher.init(true, new ParametersWithIV(new KeyParameter(key, keyOff, 32), new byte[8]));
        cipher.processBytes(r, rOff, (int) rlen, r, rOff);
    }
}
