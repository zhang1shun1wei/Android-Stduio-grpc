package com.mi.car.jsse.easysec.crypto.engines;

public class ARIAWrapEngine extends RFC3394WrapEngine {
    public ARIAWrapEngine() {
        super(new ARIAEngine());
    }

    public ARIAWrapEngine(boolean useReverseDirection) {
        super(new ARIAEngine(), useReverseDirection);
    }
}
