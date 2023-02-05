package com.mi.car.jsse.easysec.jce.spec;

public class GOST28147ParameterSpec extends com.mi.car.jsse.easysec.jcajce.spec.GOST28147ParameterSpec {
    public GOST28147ParameterSpec(byte[] sBox) {
        super(sBox);
    }

    public GOST28147ParameterSpec(byte[] sBox, byte[] iv) {
        super(sBox, iv);
    }

    public GOST28147ParameterSpec(String sBoxName) {
        super(sBoxName);
    }

    public GOST28147ParameterSpec(String sBoxName, byte[] iv) {
        super(sBoxName, iv);
    }
}
