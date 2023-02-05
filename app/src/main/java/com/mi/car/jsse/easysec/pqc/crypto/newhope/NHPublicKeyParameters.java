package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;

public class NHPublicKeyParameters extends AsymmetricKeyParameter {
    final byte[] pubData;

    public NHPublicKeyParameters(byte[] pubData2) {
        super(false);
        this.pubData = Arrays.clone(pubData2);
    }

    public byte[] getPubData() {
        return Arrays.clone(this.pubData);
    }
}
