package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

class PK {
    final byte[] root;
    final byte[] seed;

    PK(byte[] seed2, byte[] root2) {
        this.seed = seed2;
        this.root = root2;
    }
}
