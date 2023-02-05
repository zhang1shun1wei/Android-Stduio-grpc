package com.mi.car.jsse.easysec.jce.interfaces;

import com.mi.car.jsse.easysec.jce.spec.GOST3410PublicKeyParameterSetSpec;

public interface GOST3410Params {
    String getDigestParamSetOID();

    String getEncryptionParamSetOID();

    String getPublicKeyParamSetOID();

    GOST3410PublicKeyParameterSetSpec getPublicKeyParameters();
}
