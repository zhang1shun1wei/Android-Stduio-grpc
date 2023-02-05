package com.mi.car.jsse.easysec.jce.interfaces;

import com.mi.car.jsse.easysec.jce.spec.ElGamalParameterSpec;
import javax.crypto.interfaces.DHKey;

public interface ElGamalKey extends DHKey {
    ElGamalParameterSpec getParameters();
}
