package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

/* access modifiers changed from: package-private */
public class ECUtil {
    ECUtil() {
    }

    static ECCurve convertCurve(EllipticCurve ec, BigInteger order, int cofactor) {
        ECField field = ec.getField();
        BigInteger a = ec.getA();
        BigInteger b = ec.getB();
        if (field instanceof ECFieldFp) {
            return new ECCurve.Fp(((ECFieldFp) field).getP(), a, b, order, BigInteger.valueOf((long) cofactor));
        }
        ECFieldF2m fieldF2m = (ECFieldF2m) field;
        int m = fieldF2m.getM();
        int[] ks = convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
        return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b, order, BigInteger.valueOf((long) cofactor));
    }

    static int[] convertMidTerms(int[] k) {
        int[] res = new int[3];
        if (k.length == 1) {
            res[0] = k[0];
        } else if (k.length != 3) {
            throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
        } else if (k[0] < k[1] && k[0] < k[2]) {
            res[0] = k[0];
            if (k[1] < k[2]) {
                res[1] = k[1];
                res[2] = k[2];
            } else {
                res[1] = k[2];
                res[2] = k[1];
            }
        } else if (k[1] < k[2]) {
            res[0] = k[1];
            if (k[0] < k[2]) {
                res[1] = k[0];
                res[2] = k[2];
            } else {
                res[1] = k[2];
                res[2] = k[0];
            }
        } else {
            res[0] = k[2];
            if (k[0] < k[1]) {
                res[1] = k[0];
                res[2] = k[1];
            } else {
                res[1] = k[1];
                res[2] = k[0];
            }
        }
        return res;
    }

    static AlgorithmParameterSpec createInitSpec(String curveName) {
        return new ECGenParameterSpec(curveName);
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, String curveName) {
        return getAlgorithmParameters(crypto, new ECGenParameterSpec(curveName));
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, AlgorithmParameterSpec initSpec) {
        try {
            AlgorithmParameters ecAlgParams = crypto.getHelper().createAlgorithmParameters("EC");
            ecAlgParams.init(initSpec);
            if (((ECParameterSpec) ecAlgParams.getParameterSpec(ECParameterSpec.class)) != null) {
                return ecAlgParams;
            }
            return null;
        } catch (AssertionError | Exception e) {
        }
        return null;
    }

    static ECParameterSpec getECParameterSpec(JcaTlsCrypto crypto, String curveName) {
        return getECParameterSpec(crypto, createInitSpec(curveName));
    }

    static ECParameterSpec getECParameterSpec(JcaTlsCrypto crypto, AlgorithmParameterSpec initSpec) {
        try {
            KeyPairGenerator kpGen = crypto.getHelper().createKeyPairGenerator("EC");
            kpGen.initialize(initSpec, crypto.getSecureRandom());
            try {
                AlgorithmParameters ecAlgParams = crypto.getHelper().createAlgorithmParameters("EC");
                ecAlgParams.init(initSpec);
                ECParameterSpec ecSpec = (ECParameterSpec) ecAlgParams.getParameterSpec(ECParameterSpec.class);
                if (ecSpec != null) {
                    return ecSpec;
                }
            } catch (AssertionError | Exception e) {
            }
            try {
                return ((ECKey) kpGen.generateKeyPair().getPrivate()).getParams();
            } catch (AssertionError | Exception e2) {
                return null;
            }
        } catch (AssertionError e3) {
            return null;
        } catch (Exception e4) {
            return null;
        }
    }

    static boolean isECPrivateKey(PrivateKey key) {
        return (key instanceof ECPrivateKey) || "EC".equalsIgnoreCase(key.getAlgorithm());
    }

    static boolean isCurveSupported(JcaTlsCrypto crypto, String curveName) {
        return curveName != null && isCurveSupported(crypto, new ECGenParameterSpec(curveName));
    }

    static boolean isCurveSupported(JcaTlsCrypto crypto, ECGenParameterSpec initSpec) {
        return getECParameterSpec(crypto, initSpec) != null;
    }
}
