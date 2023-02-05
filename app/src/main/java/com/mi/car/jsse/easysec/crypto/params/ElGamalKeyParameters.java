package com.mi.car.jsse.easysec.crypto.params;

public class ElGamalKeyParameters extends AsymmetricKeyParameter {
    private ElGamalParameters params;

    protected ElGamalKeyParameters(boolean isPrivate, ElGamalParameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public ElGamalParameters getParameters() {
        return this.params;
    }

    public int hashCode() {
        if (this.params != null) {
            return this.params.hashCode();
        }
        return 0;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof ElGamalKeyParameters)) {
            return false;
        }
        ElGamalKeyParameters dhKey = (ElGamalKeyParameters) obj;
        if (this.params != null) {
            return this.params.equals(dhKey.getParameters());
        }
        if (dhKey.getParameters() == null) {
            return true;
        }
        return false;
    }
}
