package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class SPHINCSPlusPublicKeyParameters extends SPHINCSPlusKeyParameters {
    private final PK pk;

    public SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters parameters, byte[] pkEncoded) {
        super(false, parameters);
        int n = parameters.getEngine().N;
        if (pkEncoded.length != n * 2) {
            throw new IllegalArgumentException("public key encoding does not match parameters");
        }
        this.pk = new PK(Arrays.copyOfRange(pkEncoded, 0, n), Arrays.copyOfRange(pkEncoded, n, n * 2));
    }

    SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters parameters, PK pk2) {
        super(false, parameters);
        this.pk = pk2;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.pk.seed);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.pk.root);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(Pack.intToBigEndian(SPHINCSPlusParameters.getID(getParameters()).intValue()), this.pk.seed, this.pk.root);
    }
}
