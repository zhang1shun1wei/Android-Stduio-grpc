package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class SPHINCSPlusPrivateKeyParameters extends SPHINCSPlusKeyParameters {
    final PK pk;
    final SK sk;

    public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters parameters, byte[] skpkEncoded) {
        super(true, parameters);
        int n = parameters.getEngine().N;
        if (skpkEncoded.length != n * 4) {
            throw new IllegalArgumentException("private key encoding does not match parameters");
        }
        this.sk = new SK(Arrays.copyOfRange(skpkEncoded, 0, n), Arrays.copyOfRange(skpkEncoded, n, n * 2));
        this.pk = new PK(Arrays.copyOfRange(skpkEncoded, n * 2, n * 3), Arrays.copyOfRange(skpkEncoded, n * 3, n * 4));
    }

    SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters parameters, SK sk2, PK pk2) {
        super(true, parameters);
        this.sk = sk2;
        this.pk = pk2;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.sk.seed);
    }

    public byte[] getPrf() {
        return Arrays.clone(this.sk.prf);
    }

    public byte[] getPublicSeed() {
        return Arrays.clone(this.pk.seed);
    }

    public byte[] getPublicKey() {
        return Arrays.concatenate(this.pk.seed, this.pk.root);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(Pack.intToBigEndian(SPHINCSPlusParameters.getID(getParameters()).intValue()), Arrays.concatenate(this.sk.seed, this.sk.prf, this.pk.seed, this.pk.root));
    }

    public byte[] getEncodedPublicKey() {
        return Arrays.concatenate(Pack.intToBigEndian(SPHINCSPlusParameters.getID(getParameters()).intValue()), this.pk.seed, this.pk.root);
    }
}
