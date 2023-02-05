package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class McElieceKeyParameters extends AsymmetricKeyParameter {
    private McElieceParameters params;

    public McElieceKeyParameters(boolean isPrivate, McElieceParameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public McElieceParameters getParameters() {
        return this.params;
    }
}
