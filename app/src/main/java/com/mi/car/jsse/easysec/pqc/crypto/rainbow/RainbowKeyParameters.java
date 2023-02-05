package com.mi.car.jsse.easysec.pqc.crypto.rainbow;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class RainbowKeyParameters extends AsymmetricKeyParameter {
    private int docLength;

    public RainbowKeyParameters(boolean isPrivate, int docLength2) {
        super(isPrivate);
        this.docLength = docLength2;
    }

    public int getDocLength() {
        return this.docLength;
    }
}
