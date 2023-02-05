package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Vector;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2mField;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GoppaCode;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.Permutation;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialGF2mSmallM;

final class McElieceCCA2Primitives {
    private McElieceCCA2Primitives() {
    }

    public static GF2Vector encryptionPrimitive(McElieceCCA2PublicKeyParameters pubKey, GF2Vector m, GF2Vector z) {
        return (GF2Vector) pubKey.getG().leftMultiplyLeftCompactForm(m).add(z);
    }

    public static GF2Vector[] decryptionPrimitive(McElieceCCA2PrivateKeyParameters privKey, GF2Vector c) {
        int k = privKey.getK();
        Permutation p = privKey.getP();
        GF2mField field = privKey.getField();
        PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
        GF2Matrix h = privKey.getH();
        PolynomialGF2mSmallM[] q = privKey.getQInv();
        GF2Vector cPInv = (GF2Vector) c.multiply(p.computeInverse());
        GF2Vector errors = GoppaCode.syndromeDecode((GF2Vector) h.rightMultiply(cPInv), field, gp, q);
        return new GF2Vector[]{((GF2Vector) ((GF2Vector) cPInv.add(errors)).multiply(p)).extractRightVector(k), (GF2Vector) errors.multiply(p)};
    }
}
