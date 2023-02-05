package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

class SK {
    final byte[] prf;
    final byte[] seed;

    SK(byte[] seed2, byte[] prf2) {
        this.seed = seed2;
        this.prf = prf2;
    }
}
