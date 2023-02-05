package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.IntegerPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.ProductFormPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.util.Util;

public class NTRUEncryptionKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private NTRUEncryptionKeyGenerationParameters params;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        this.params = (NTRUEncryptionKeyGenerationParameters) param;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        Polynomial t;
        IntegerPolynomial f;
        IntegerPolynomial fq;
        DenseTernaryPolynomial g;
        int N = this.params.N;
        int q = this.params.q;
        int df = this.params.df;
        int df1 = this.params.df1;
        int df2 = this.params.df2;
        int df3 = this.params.df3;
        int dg = this.params.dg;
        boolean fastFp = this.params.fastFp;
        boolean sparse = this.params.sparse;
        IntegerPolynomial fp = null;
        while (true) {
            if (fastFp) {
                t = this.params.polyType == 0 ? Util.generateRandomTernary(N, df, df, sparse, this.params.getRandom()) : ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3, this.params.getRandom());
                f = t.toIntegerPolynomial();
                f.mult(3);
                int[] iArr = f.coeffs;
                iArr[0] = iArr[0] + 1;
            } else {
                t = this.params.polyType == 0 ? Util.generateRandomTernary(N, df, df - 1, sparse, this.params.getRandom()) : ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3 - 1, this.params.getRandom());
                f = t.toIntegerPolynomial();
                fp = f.invertF3();
                if (fp == null) {
                    continue;
                }
            }
            fq = f.invertFq(q);
            if (fq != null) {
                break;
            }
        }
        if (fastFp) {
            fp = new IntegerPolynomial(N);
            fp.coeffs[0] = 1;
        }
        do {
            g = DenseTernaryPolynomial.generateRandom(N, dg, dg - 1, this.params.getRandom());
        } while (g.invertFq(q) == null);
        IntegerPolynomial h = g.mult(fq, q);
        h.mult3(q);
        h.ensurePositive(q);
        g.clear();
        fq.clear();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new NTRUEncryptionPublicKeyParameters(h, this.params.getEncryptionParameters()), (AsymmetricKeyParameter) new NTRUEncryptionPrivateKeyParameters(h, t, fp, this.params.getEncryptionParameters()));
    }
}
