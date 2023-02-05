package com.mi.car.jsse.easysec.pqc.crypto.lms;

public interface LMSContextBasedSigner {
    LMSContext generateLMSContext();

    byte[] generateSignature(LMSContext lMSContext);

    long getUsagesRemaining();
}
