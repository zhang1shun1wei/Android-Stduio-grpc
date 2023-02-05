package com.mi.car.jsse.easysec.pqc.jcajce.interfaces;

import com.mi.car.jsse.easysec.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import java.security.Key;

public interface SPHINCSPlusKey extends Key {
    SPHINCSPlusParameterSpec getParameterSpec();
}
