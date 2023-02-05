package com.mi.car.jsse.easysec.pqc.jcajce.interfaces;

import com.mi.car.jsse.easysec.pqc.jcajce.spec.CMCEParameterSpec;
import java.security.Key;

public interface CMCEKey extends Key {
    CMCEParameterSpec getParameterSpec();
}
