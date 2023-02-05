package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.pqc.crypto.lms.LMOtsParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSigParameters;
import java.security.spec.AlgorithmParameterSpec;

public class LMSKeyGenParameterSpec implements AlgorithmParameterSpec {
    private final LMOtsParameters lmOtsParameters;
    private final LMSigParameters lmSigParams;

    public LMSKeyGenParameterSpec(LMSigParameters lmSigParams2, LMOtsParameters lmOtsParameters2) {
        this.lmSigParams = lmSigParams2;
        this.lmOtsParameters = lmOtsParameters2;
    }

    public LMSigParameters getSigParams() {
        return this.lmSigParams;
    }

    public LMOtsParameters getOtsParams() {
        return this.lmOtsParameters;
    }
}
