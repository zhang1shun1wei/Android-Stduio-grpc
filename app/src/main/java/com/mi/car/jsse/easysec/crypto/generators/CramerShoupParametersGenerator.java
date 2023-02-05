package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.params.CramerShoupParameters;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class CramerShoupParametersGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1L);
    private int size;
    private int certainty;
    private SecureRandom random;

    public CramerShoupParametersGenerator() {
    }

    public void init(int size, int certainty, SecureRandom random) {
        this.size = size;
        this.certainty = certainty;
        this.random = random;
    }

    public CramerShoupParameters generateParameters() {
        BigInteger[] safePrimes = CramerShoupParametersGenerator.ParametersHelper.generateSafePrimes(this.size, this.certainty, this.random);
        BigInteger q = safePrimes[1];
        BigInteger g1 = CramerShoupParametersGenerator.ParametersHelper.selectGenerator(q, this.random);

        BigInteger g2;
        for(g2 = CramerShoupParametersGenerator.ParametersHelper.selectGenerator(q, this.random); g1.equals(g2); g2 = CramerShoupParametersGenerator.ParametersHelper.selectGenerator(q, this.random)) {
        }

        return new CramerShoupParameters(q, g1, g2, new SHA256Digest());
    }

    public CramerShoupParameters generateParameters(DHParameters dhParams) {
        BigInteger p = dhParams.getP();
        BigInteger g1 = dhParams.getG();

        BigInteger g2;
        for(g2 = CramerShoupParametersGenerator.ParametersHelper.selectGenerator(p, this.random); g1.equals(g2); g2 = CramerShoupParametersGenerator.ParametersHelper.selectGenerator(p, this.random)) {
        }

        return new CramerShoupParameters(p, g1, g2, new SHA256Digest());
    }

    private static class ParametersHelper {
        private static final BigInteger TWO = BigInteger.valueOf(2L);

        private ParametersHelper() {
        }

        static BigInteger[] generateSafePrimes(int size, int certainty, SecureRandom random) {
            int qLength = size - 1;

            BigInteger p;
            BigInteger q;
            do {
                do {
                    q = BigIntegers.createRandomPrime(qLength, 2, random);
                    p = q.shiftLeft(1).add(CramerShoupParametersGenerator.ONE);
                } while(!p.isProbablePrime(certainty));
            } while(certainty > 2 && !q.isProbablePrime(certainty));

            return new BigInteger[]{p, q};
        }

        static BigInteger selectGenerator(BigInteger p, SecureRandom random) {
            BigInteger pMinusTwo = p.subtract(TWO);

            BigInteger g;
            do {
                BigInteger h = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);
                g = h.modPow(TWO, p);
            } while(g.equals(CramerShoupParametersGenerator.ONE));

            return g;
        }
    }
}
