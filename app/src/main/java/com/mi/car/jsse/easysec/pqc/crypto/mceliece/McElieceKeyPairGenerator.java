package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2mField;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GoppaCode;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.Permutation;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialRingGF2m;
import java.security.SecureRandom;

public class McElieceKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";
    private int fieldPoly;
    private boolean initialized = false;
    private int m;
    private McElieceKeyGenerationParameters mcElieceParams;
    private int n;
    private SecureRandom random;
    private int t;

    private void initializeDefault() {
        initialize(new McElieceKeyGenerationParameters(null, new McElieceParameters()));
    }

    private void initialize(KeyGenerationParameters param) {
        this.mcElieceParams = (McElieceKeyGenerationParameters) param;
        this.random = param.getRandom();
        this.m = this.mcElieceParams.getParameters().getM();
        this.n = this.mcElieceParams.getParameters().getN();
        this.t = this.mcElieceParams.getParameters().getT();
        this.fieldPoly = this.mcElieceParams.getParameters().getFieldPoly();
        this.initialized = true;
    }

    private AsymmetricCipherKeyPair genKeyPair() {
        if (!this.initialized) {
            initializeDefault();
        }
        GF2mField field = new GF2mField(this.m, this.fieldPoly);
        PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, this.t, 'I', this.random);
        new PolynomialRingGF2m(field, gp).getSquareRootMatrix();
        GoppaCode.MaMaPe mmp = GoppaCode.computeSystematicForm(GoppaCode.createCanonicalCheckMatrix(field, gp), this.random);
        GF2Matrix shortH = mmp.getSecondMatrix();
        Permutation p1 = mmp.getPermutation();
        GF2Matrix shortG = (GF2Matrix) shortH.computeTranspose();
        GF2Matrix gPrime = shortG.extendLeftCompactForm();
        int k = shortG.getNumRows();
        GF2Matrix[] matrixSandInverse = GF2Matrix.createRandomRegularMatrixAndItsInverse(k, this.random);
        Permutation p2 = new Permutation(this.n, this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new McEliecePublicKeyParameters(this.n, this.t, (GF2Matrix) ((GF2Matrix) matrixSandInverse[0].rightMultiply(gPrime)).rightMultiply(p2)), (AsymmetricKeyParameter) new McEliecePrivateKeyParameters(this.n, k, field, gp, p1, p2, matrixSandInverse[1]));
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        initialize(param);
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }
}
