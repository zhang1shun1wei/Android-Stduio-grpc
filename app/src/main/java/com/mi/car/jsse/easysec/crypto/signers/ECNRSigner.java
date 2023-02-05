package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DSAExt;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.generators.ECKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.params.ECKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.ECKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ECNRSigner implements DSAExt {
    private boolean forSigning;
    private ECKeyParameters key;
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public void init(boolean forSigning2, CipherParameters param) {
        this.forSigning = forSigning2;
        if (!forSigning2) {
            this.key = (ECPublicKeyParameters) param;
        } else if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.random = rParam.getRandom();
            this.key = (ECPrivateKeyParameters) rParam.getParameters();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.key = (ECPrivateKeyParameters) param;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSAExt
    public BigInteger getOrder() {
        return this.key.getParameters().getN();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public BigInteger[] generateSignature(byte[] digest) {
        AsymmetricCipherKeyPair tempPair;
        BigInteger r;
        if (!this.forSigning) {
            throw new IllegalStateException("not initialised for signing");
        }
        BigInteger n = getOrder();
        BigInteger e = new BigInteger(1, digest);
        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters) this.key;
        if (e.compareTo(n) >= 0) {
            throw new DataLengthException("input too large for ECNR key");
        }
        do {
            ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
            keyGen.init(new ECKeyGenerationParameters(privKey.getParameters(), this.random));
            tempPair = keyGen.generateKeyPair();
            r = ((ECPublicKeyParameters) tempPair.getPublic()).getQ().getAffineXCoord().toBigInteger().add(e).mod(n);
        } while (r.equals(ECConstants.ZERO));
        return new BigInteger[]{r, ((ECPrivateKeyParameters) tempPair.getPrivate()).getD().subtract(r.multiply(privKey.getD())).mod(n)};
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public boolean verifySignature(byte[] digest, BigInteger r, BigInteger s) {
        if (this.forSigning) {
            throw new IllegalStateException("not initialised for verifying");
        }
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters) this.key;
        BigInteger n = pubKey.getParameters().getN();
        int nBitLength = n.bitLength();
        BigInteger e = new BigInteger(1, digest);
        if (e.bitLength() > nBitLength) {
            throw new DataLengthException("input too large for ECNR key.");
        }
        BigInteger t = extractT(pubKey, r, s);
        if (t == null || !t.equals(e.mod(n))) {
            return false;
        }
        return true;
    }

    public byte[] getRecoveredMessage(BigInteger r, BigInteger s) {
        if (this.forSigning) {
            throw new IllegalStateException("not initialised for verifying/recovery");
        }
        BigInteger t = extractT((ECPublicKeyParameters) this.key, r, s);
        if (t != null) {
            return BigIntegers.asUnsignedByteArray(t);
        }
        return null;
    }

    private BigInteger extractT(ECPublicKeyParameters pubKey, BigInteger r, BigInteger s) {
        BigInteger n = pubKey.getParameters().getN();
        if (r.compareTo(ECConstants.ONE) < 0 || r.compareTo(n) >= 0 || s.compareTo(ECConstants.ZERO) < 0 || s.compareTo(n) >= 0) {
            return null;
        }
        ECPoint P = ECAlgorithms.sumOfTwoMultiplies(pubKey.getParameters().getG(), s, pubKey.getQ(), r).normalize();
        if (!P.isInfinity()) {
            return r.subtract(P.getAffineXCoord().toBigInteger()).mod(n);
        }
        return null;
    }
}
