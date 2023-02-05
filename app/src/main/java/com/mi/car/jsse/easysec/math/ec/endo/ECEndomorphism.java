package com.mi.car.jsse.easysec.math.ec.endo;

import com.mi.car.jsse.easysec.math.ec.ECPointMap;

public interface ECEndomorphism {
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}
