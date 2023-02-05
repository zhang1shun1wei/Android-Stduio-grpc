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
import java.security.SecureRandom;

public class McElieceCCA2KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2";
    private int fieldPoly;
    private boolean initialized = false;
    private int m;
    private McElieceCCA2KeyGenerationParameters mcElieceCCA2Params;
    private int n;
    private SecureRandom random;
    private int t;

    private void initializeDefault() {
        init(new McElieceCCA2KeyGenerationParameters(null, new McElieceCCA2Parameters()));
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        this.mcElieceCCA2Params = (McElieceCCA2KeyGenerationParameters) param;
        this.random = param.getRandom();
        this.m = this.mcElieceCCA2Params.getParameters().getM();
        this.n = this.mcElieceCCA2Params.getParameters().getN();
        this.t = this.mcElieceCCA2Params.getParameters().getT();
        this.fieldPoly = this.mcElieceCCA2Params.getParameters().getFieldPoly();
        this.initialized = true;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        if (!this.initialized) {
            initializeDefault();
        }
        GF2mField field = new GF2mField(this.m, this.fieldPoly);
        PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, this.t, 'I', this.random);
        GoppaCode.MaMaPe mmp = GoppaCode.computeSystematicForm(GoppaCode.createCanonicalCheckMatrix(field, gp), this.random);
        GF2Matrix shortH = mmp.getSecondMatrix();
        Permutation p = mmp.getPermutation();
        GF2Matrix shortG = (GF2Matrix) shortH.computeTranspose();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new McElieceCCA2PublicKeyParameters(this.n, this.t, shortG, this.mcElieceCCA2Params.getParameters().getDigest()), (AsymmetricKeyParameter) new McElieceCCA2PrivateKeyParameters(this.n, shortG.getNumRows(), field, gp, p, this.mcElieceCCA2Params.getParameters().getDigest()));
    }
}
