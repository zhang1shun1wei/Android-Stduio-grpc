package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.digests.SM3Digest;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithID;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;

public class SM2Signer implements Signer, ECConstants {
    private final Digest digest;
    private ECKeyParameters ecKey;
    private ECDomainParameters ecParams;
    private final DSAEncoding encoding;
    private final DSAKCalculator kCalculator;
    private ECPoint pubPoint;
    private byte[] z;

    public SM2Signer() {
        this(StandardDSAEncoding.INSTANCE, new SM3Digest());
    }

    public SM2Signer(Digest digest2) {
        this(StandardDSAEncoding.INSTANCE, digest2);
    }

    public SM2Signer(DSAEncoding encoding2) {
        this.kCalculator = new RandomDSAKCalculator();
        this.encoding = encoding2;
        this.digest = new SM3Digest();
    }

    public SM2Signer(DSAEncoding encoding2, Digest digest2) {
        this.kCalculator = new RandomDSAKCalculator();
        this.encoding = encoding2;
        this.digest = digest2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void init(boolean forSigning, CipherParameters param) {
        byte[] userID;
        CipherParameters baseParam;
        if (param instanceof ParametersWithID) {
            baseParam = ((ParametersWithID) param).getParameters();
            userID = ((ParametersWithID) param).getID();
            if (userID.length >= 8192) {
                throw new IllegalArgumentException("SM2 user ID must be less than 2^16 bits long");
            }
        } else {
            baseParam = param;
            userID = Hex.decodeStrict("31323334353637383132333435363738");
        }
        if (forSigning) {
            if (baseParam instanceof ParametersWithRandom) {
                ParametersWithRandom rParam = (ParametersWithRandom) baseParam;
                this.ecKey = (ECKeyParameters) rParam.getParameters();
                this.ecParams = this.ecKey.getParameters();
                this.kCalculator.init(this.ecParams.getN(), rParam.getRandom());
            } else {
                this.ecKey = (ECKeyParameters) baseParam;
                this.ecParams = this.ecKey.getParameters();
                this.kCalculator.init(this.ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
            }
            this.pubPoint = createBasePointMultiplier().multiply(this.ecParams.getG(), ((ECPrivateKeyParameters) this.ecKey).getD()).normalize();
        } else {
            this.ecKey = (ECKeyParameters) baseParam;
            this.ecParams = this.ecKey.getParameters();
            this.pubPoint = ((ECPublicKeyParameters) this.ecKey).getQ();
        }
        this.z = getZ(userID);
        this.digest.update(this.z, 0, this.z.length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte b) {
        this.digest.update(b);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte[] in, int off, int len) {
        this.digest.update(in, off, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        try {
            BigInteger[] rs = this.encoding.decode(this.ecParams.getN(), signature);
            return verifySignature(rs[0], rs[1]);
        } catch (Exception e) {
            return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void reset() {
        this.digest.reset();
        if (this.z != null) {
            this.digest.update(this.z, 0, this.z.length);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public byte[] generateSignature() throws CryptoException {
        byte[] eHash = digestDoFinal();
        BigInteger n = this.ecParams.getN();
        BigInteger e = calculateE(n, eHash);
        BigInteger d = ((ECPrivateKeyParameters) this.ecKey).getD();
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        while (true) {
            BigInteger k = this.kCalculator.nextK();
            BigInteger r = e.add(basePointMultiplier.multiply(this.ecParams.getG(), k).normalize().getAffineXCoord().toBigInteger()).mod(n);
            if (!r.equals(ZERO) && !r.add(k).equals(n)) {
                BigInteger s = BigIntegers.modOddInverse(n, d.add(ONE)).multiply(k.subtract(r.multiply(d)).mod(n)).mod(n);
                if (!s.equals(ZERO)) {
                    try {
                        return this.encoding.encode(this.ecParams.getN(), r, s);
                    } catch (Exception ex) {
                        throw new CryptoException("unable to encode signature: " + ex.getMessage(), ex);
                    }
                }
            }
        }
    }

    private boolean verifySignature(BigInteger r, BigInteger s) {
        BigInteger n = this.ecParams.getN();
        if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0) {
            return false;
        }
        if (s.compareTo(ONE) < 0 || s.compareTo(n) >= 0) {
            return false;
        }
        BigInteger e = calculateE(n, digestDoFinal());
        BigInteger t = r.add(s).mod(n);
        if (t.equals(ZERO)) {
            return false;
        }
        ECPoint x1y1 = ECAlgorithms.sumOfTwoMultiplies(this.ecParams.getG(), s, ((ECPublicKeyParameters) this.ecKey).getQ(), t).normalize();
        if (x1y1.isInfinity()) {
            return false;
        }
        return e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n).equals(r);
    }

    private byte[] digestDoFinal() {
        byte[] result = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(result, 0);
        reset();
        return result;
    }

    private byte[] getZ(byte[] userID) {
        this.digest.reset();
        addUserID(this.digest, userID);
        addFieldElement(this.digest, this.ecParams.getCurve().getA());
        addFieldElement(this.digest, this.ecParams.getCurve().getB());
        addFieldElement(this.digest, this.ecParams.getG().getAffineXCoord());
        addFieldElement(this.digest, this.ecParams.getG().getAffineYCoord());
        addFieldElement(this.digest, this.pubPoint.getAffineXCoord());
        addFieldElement(this.digest, this.pubPoint.getAffineYCoord());
        byte[] result = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(result, 0);
        return result;
    }

    private void addUserID(Digest digest2, byte[] userID) {
        int len = userID.length * 8;
        digest2.update((byte) ((len >> 8) & GF2Field.MASK));
        digest2.update((byte) (len & GF2Field.MASK));
        digest2.update(userID, 0, userID.length);
    }

    private void addFieldElement(Digest digest2, ECFieldElement v) {
        byte[] p = v.getEncoded();
        digest2.update(p, 0, p.length);
    }

    /* access modifiers changed from: protected */
    public ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    /* access modifiers changed from: protected */
    public BigInteger calculateE(BigInteger n, byte[] message) {
        return new BigInteger(1, message);
    }
}
