package com.mi.car.jsse.easysec.pqc.jcajce.interfaces;

import com.mi.car.jsse.easysec.pqc.jcajce.spec.SABERParameterSpec;
import java.security.Key;

public interface SABERKey extends Key {
    SABERParameterSpec getParameterSpec();
}
