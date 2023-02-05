package com.mi.car.jsse.easysec.crypto.params;

public class CramerShoupKeyParameters extends AsymmetricKeyParameter {
    private CramerShoupParameters params;

    protected CramerShoupKeyParameters(boolean isPrivate, CramerShoupParameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public CramerShoupParameters getParameters() {
        return this.params;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof CramerShoupKeyParameters)) {
            return false;
        }
        CramerShoupKeyParameters csKey = (CramerShoupKeyParameters) obj;
        if (this.params != null) {
            return this.params.equals(csKey.getParameters());
        }
        if (csKey.getParameters() == null) {
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
