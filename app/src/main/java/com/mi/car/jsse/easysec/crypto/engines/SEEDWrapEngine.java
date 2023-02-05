package com.mi.car.jsse.easysec.crypto.engines;

public class SEEDWrapEngine extends RFC3394WrapEngine {
    public SEEDWrapEngine() {
        super(new SEEDEngine());
    }
}
