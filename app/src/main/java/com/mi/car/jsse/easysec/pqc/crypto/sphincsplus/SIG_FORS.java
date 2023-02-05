package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

class SIG_FORS {
    final byte[][] authPath;
    final byte[] sk;

    SIG_FORS(byte[] sk2, byte[][] authPath2) {
        this.authPath = authPath2;
        this.sk = sk2;
    }

    /* access modifiers changed from: package-private */
    public byte[] getSK() {
        return this.sk;
    }

    public byte[][] getAuthPath() {
        return this.authPath;
    }
}
