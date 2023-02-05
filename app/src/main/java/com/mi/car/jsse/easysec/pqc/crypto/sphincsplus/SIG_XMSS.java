package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

class SIG_XMSS {
    final byte[][] auth;
    final byte[] sig;

    public SIG_XMSS(byte[] sig2, byte[][] auth2) {
        this.sig = sig2;
        this.auth = auth2;
    }

    public byte[] getWOTSSig() {
        return this.sig;
    }

    public byte[][] getXMSSAUTH() {
        return this.auth;
    }
}
