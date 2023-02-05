package com.mi.car.jsse.easysec.crypto;

public interface SkippingCipher {
    long getPosition();

    long seekTo(long j);

    long skip(long j);
}
