package com.mi.car.jsse.easysec.pqc.crypto.lms;

public interface LMSContextBasedVerifier {
    LMSContext generateLMSContext(byte[] bArr);

    boolean verify(LMSContext lMSContext);
}
