package com.mi.car.jsse.easysec.pqc.crypto.lms;

public class LMSParameters {
    private final LMOtsParameters lmOTSParam;
    private final LMSigParameters lmSigParam;

    public LMSParameters(LMSigParameters lmSigParam2, LMOtsParameters lmOTSParam2) {
        this.lmSigParam = lmSigParam2;
        this.lmOTSParam = lmOTSParam2;
    }

    public LMSigParameters getLMSigParam() {
        return this.lmSigParam;
    }

    public LMOtsParameters getLMOTSParam() {
        return this.lmOTSParam;
    }
}
