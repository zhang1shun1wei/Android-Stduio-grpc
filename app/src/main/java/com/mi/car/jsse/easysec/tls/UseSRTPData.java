package com.mi.car.jsse.easysec.tls;

public class UseSRTPData {
    protected byte[] mki;
    protected int[] protectionProfiles;

    public UseSRTPData(int[] protectionProfiles2, byte[] mki2) {
        if (TlsUtils.isNullOrEmpty(protectionProfiles2) || protectionProfiles2.length >= 32768) {
            throw new IllegalArgumentException("'protectionProfiles' must have length from 1 to (2^15 - 1)");
        }
        if (mki2 == null) {
            mki2 = TlsUtils.EMPTY_BYTES;
        } else if (mki2.length > 255) {
            throw new IllegalArgumentException("'mki' cannot be longer than 255 bytes");
        }
        this.protectionProfiles = protectionProfiles2;
        this.mki = mki2;
    }

    public int[] getProtectionProfiles() {
        return this.protectionProfiles;
    }

    public byte[] getMki() {
        return this.mki;
    }
}
