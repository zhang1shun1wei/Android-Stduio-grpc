package com.mi.car.jsse.easysec.crypto.params;

public class ECKeyParameters extends AsymmetricKeyParameter {
    private final ECDomainParameters parameters;

    protected ECKeyParameters(boolean isPrivate, ECDomainParameters parameters2) {
        super(isPrivate);
        if (parameters2 == null) {
            throw new NullPointerException("'parameters' cannot be null");
        }
        this.parameters = parameters2;
    }

    public ECDomainParameters getParameters() {
        return this.parameters;
    }
}
