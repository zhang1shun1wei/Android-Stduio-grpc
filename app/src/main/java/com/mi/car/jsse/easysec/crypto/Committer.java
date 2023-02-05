package com.mi.car.jsse.easysec.crypto;

public interface Committer {
    Commitment commit(byte[] bArr);

    boolean isRevealed(Commitment commitment, byte[] bArr);
}
