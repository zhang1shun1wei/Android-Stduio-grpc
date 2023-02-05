package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

public class McElieceCCA2Parameters extends McElieceParameters {
    private final String digest;

    public McElieceCCA2Parameters() {
        this(11, 50, "SHA-256");
    }

    public McElieceCCA2Parameters(String digest2) {
        this(11, 50, digest2);
    }

    public McElieceCCA2Parameters(int keysize) {
        this(keysize, "SHA-256");
    }

    public McElieceCCA2Parameters(int keysize, String digest2) {
        super(keysize);
        this.digest = digest2;
    }

    public McElieceCCA2Parameters(int m, int t) {
        this(m, t, "SHA-256");
    }

    public McElieceCCA2Parameters(int m, int t, String digest2) {
        super(m, t);
        this.digest = digest2;
    }

    public McElieceCCA2Parameters(int m, int t, int poly) {
        this(m, t, poly, "SHA-256");
    }

    public McElieceCCA2Parameters(int m, int t, int poly, String digest2) {
        super(m, t, poly);
        this.digest = digest2;
    }

    public String getDigest() {
        return this.digest;
    }
}
