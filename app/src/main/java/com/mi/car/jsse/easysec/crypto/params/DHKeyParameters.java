package com.mi.car.jsse.easysec.crypto.params;

public class DHKeyParameters extends AsymmetricKeyParameter {
    private DHParameters params;

    protected DHKeyParameters(boolean isPrivate, DHParameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public DHParameters getParameters() {
        return this.params;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof DHKeyParameters)) {
            return false;
        }
        DHKeyParameters dhKey = (DHKeyParameters) obj;
        if (this.params != null) {
            return this.params.equals(dhKey.getParameters());
        }
        if (dhKey.getParameters() == null) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        int code = isPrivate() ? 0 : 1;
        if (this.params != null) {
            return code ^ this.params.hashCode();
        }
        return code;
    }
}
