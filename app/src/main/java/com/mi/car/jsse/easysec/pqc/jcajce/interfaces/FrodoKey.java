package com.mi.car.jsse.easysec.pqc.jcajce.interfaces;

import com.mi.car.jsse.easysec.pqc.jcajce.spec.FrodoParameterSpec;
import java.security.Key;

public interface FrodoKey extends Key {
    FrodoParameterSpec getParameterSpec();
}
