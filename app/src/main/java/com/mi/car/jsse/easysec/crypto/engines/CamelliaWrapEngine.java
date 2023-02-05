package com.mi.car.jsse.easysec.crypto.engines;

public class CamelliaWrapEngine extends RFC3394WrapEngine {
    public CamelliaWrapEngine() {
        super(new CamelliaEngine());
    }
}
