package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;

public class NHPrivateKeyParameters extends AsymmetricKeyParameter {
    final short[] secData;

    public NHPrivateKeyParameters(short[] secData2) {
        super(true);
        this.secData = Arrays.clone(secData2);
    }

    public short[] getSecData() {
        return Arrays.clone(this.secData);
    }
}
