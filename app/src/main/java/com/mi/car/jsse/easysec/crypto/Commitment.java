package com.mi.car.jsse.easysec.crypto;

public class Commitment {
    private final byte[] commitment;
    private final byte[] secret;

    public Commitment(byte[] secret2, byte[] commitment2) {
        this.secret = secret2;
        this.commitment = commitment2;
    }

    public byte[] getSecret() {
        return this.secret;
    }

    public byte[] getCommitment() {
        return this.commitment;
    }
}
