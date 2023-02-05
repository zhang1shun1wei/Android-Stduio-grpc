package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.SM3Digest;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithID;
import com.mi.car.jsse.easysec.crypto.params.SM2KeyExchangePrivateParameters;
import com.mi.car.jsse.easysec.crypto.params.SM2KeyExchangePublicParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Memoable;
import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;

public class SM2KeyExchange {
    private final Digest digest;
    private ECDomainParameters ecParams;
    private ECPrivateKeyParameters ephemeralKey;
    private ECPoint ephemeralPubPoint;
    private boolean initiator;
    private ECPrivateKeyParameters staticKey;
    private ECPoint staticPubPoint;
    private byte[] userID;
    private int w;

    public SM2KeyExchange() {
        this(new SM3Digest());
    }

    public SM2KeyExchange(Digest digest2) {
        this.digest = digest2;
    }

    public void init(CipherParameters privParam) {
        SM2KeyExchangePrivateParameters baseParam;
        if (privParam instanceof ParametersWithID) {
            baseParam = (SM2KeyExchangePrivateParameters) ((ParametersWithID) privParam).getParameters();
            this.userID = ((ParametersWithID) privParam).getID();
        } else {
            baseParam = (SM2KeyExchangePrivateParameters) privParam;
            this.userID = new byte[0];
        }
        this.initiator = baseParam.isInitiator();
        this.staticKey = baseParam.getStaticPrivateKey();
        this.ephemeralKey = baseParam.getEphemeralPrivateKey();
        this.ecParams = this.staticKey.getParameters();
        this.staticPubPoint = baseParam.getStaticPublicPoint();
        this.ephemeralPubPoint = baseParam.getEphemeralPublicPoint();
        this.w = (this.ecParams.getCurve().getFieldSize() / 2) - 1;
    }

    public byte[] calculateKey(int kLen, CipherParameters pubParam) {
        SM2KeyExchangePublicParameters otherPub;
        byte[] otherUserID;
        if (pubParam instanceof ParametersWithID) {
            otherPub = (SM2KeyExchangePublicParameters) ((ParametersWithID) pubParam).getParameters();
            otherUserID = ((ParametersWithID) pubParam).getID();
        } else {
            otherPub = (SM2KeyExchangePublicParameters) pubParam;
            otherUserID = new byte[0];
        }
        byte[] za = getZ(this.digest, this.userID, this.staticPubPoint);
        byte[] zb = getZ(this.digest, otherUserID, otherPub.getStaticPublicKey().getQ());
        ECPoint U = calculateU(otherPub);
        if (this.initiator) {
            return kdf(U, za, zb, kLen);
        }
        return kdf(U, zb, za, kLen);
    }

    public byte[][] calculateKeyWithConfirmation(int kLen, byte[] confirmationTag, CipherParameters pubParam) {
        SM2KeyExchangePublicParameters otherPub;
        byte[] otherUserID;
        if (pubParam instanceof ParametersWithID) {
            otherPub = (SM2KeyExchangePublicParameters) ((ParametersWithID) pubParam).getParameters();
            otherUserID = ((ParametersWithID) pubParam).getID();
        } else {
            otherPub = (SM2KeyExchangePublicParameters) pubParam;
            otherUserID = new byte[0];
        }
        if (!this.initiator || confirmationTag != null) {
            byte[] za = getZ(this.digest, this.userID, this.staticPubPoint);
            byte[] zb = getZ(this.digest, otherUserID, otherPub.getStaticPublicKey().getQ());
            ECPoint U = calculateU(otherPub);
            if (this.initiator) {
                byte[] rv = kdf(U, za, zb, kLen);
                byte[] inner = calculateInnerHash(this.digest, U, za, zb, this.ephemeralPubPoint, otherPub.getEphemeralPublicKey().getQ());
                if (!Arrays.constantTimeAreEqual(S1(this.digest, U, inner), confirmationTag)) {
                    throw new IllegalStateException("confirmation tag mismatch");
                }
                return new byte[][]{rv, S2(this.digest, U, inner)};
            }
            byte[] rv2 = kdf(U, zb, za, kLen);
            byte[] inner2 = calculateInnerHash(this.digest, U, zb, za, otherPub.getEphemeralPublicKey().getQ(), this.ephemeralPubPoint);
            return new byte[][]{rv2, S1(this.digest, U, inner2), S2(this.digest, U, inner2)};
        }
        throw new IllegalArgumentException("if initiating, confirmationTag must be set");
    }

    private ECPoint calculateU(SM2KeyExchangePublicParameters otherPub) {
        ECDomainParameters params = this.staticKey.getParameters();
        ECPoint p1 = ECAlgorithms.cleanPoint(params.getCurve(), otherPub.getStaticPublicKey().getQ());
        ECPoint p2 = ECAlgorithms.cleanPoint(params.getCurve(), otherPub.getEphemeralPublicKey().getQ());
        BigInteger x1 = reduce(this.ephemeralPubPoint.getAffineXCoord().toBigInteger());
        BigInteger x2 = reduce(p2.getAffineXCoord().toBigInteger());
        BigInteger k1 = this.ecParams.getH().multiply(this.staticKey.getD().add(x1.multiply(this.ephemeralKey.getD()))).mod(this.ecParams.getN());
        return ECAlgorithms.sumOfTwoMultiplies(p1, k1, p2, k1.multiply(x2).mod(this.ecParams.getN())).normalize();
    }

    private byte[] kdf(ECPoint u, byte[] za, byte[] zb, int klen) {
        int digestSize = this.digest.getDigestSize();
        byte[] buf = new byte[Math.max(4, digestSize)];
        byte[] rv = new byte[((klen + 7) / 8)];
        int off = 0;
        Memoable memo = null;
        Memoable copy = null;
        if (this.digest instanceof Memoable) {
            addFieldElement(this.digest, u.getAffineXCoord());
            addFieldElement(this.digest, u.getAffineYCoord());
            this.digest.update(za, 0, za.length);
            this.digest.update(zb, 0, zb.length);
            memo = (Memoable) this.digest;
            copy = memo.copy();
        }
        int ct = 0;
        while (off < rv.length) {
            if (memo != null) {
                memo.reset(copy);
            } else {
                addFieldElement(this.digest, u.getAffineXCoord());
                addFieldElement(this.digest, u.getAffineYCoord());
                this.digest.update(za, 0, za.length);
                this.digest.update(zb, 0, zb.length);
            }
            ct++;
            Pack.intToBigEndian(ct, buf, 0);
            this.digest.update(buf, 0, 4);
            this.digest.doFinal(buf, 0);
            int copyLen = Math.min(digestSize, rv.length - off);
            System.arraycopy(buf, 0, rv, off, copyLen);
            off += copyLen;
        }
        return rv;
    }

    private BigInteger reduce(BigInteger x) {
        return x.and(BigInteger.valueOf(1).shiftLeft(this.w).subtract(BigInteger.valueOf(1))).setBit(this.w);
    }

    private byte[] S1(Digest digest2, ECPoint u, byte[] inner) {
        digest2.update((byte) 2);
        addFieldElement(digest2, u.getAffineYCoord());
        digest2.update(inner, 0, inner.length);
        return digestDoFinal();
    }

    private byte[] calculateInnerHash(Digest digest2, ECPoint u, byte[] za, byte[] zb, ECPoint p1, ECPoint p2) {
        addFieldElement(digest2, u.getAffineXCoord());
        digest2.update(za, 0, za.length);
        digest2.update(zb, 0, zb.length);
        addFieldElement(digest2, p1.getAffineXCoord());
        addFieldElement(digest2, p1.getAffineYCoord());
        addFieldElement(digest2, p2.getAffineXCoord());
        addFieldElement(digest2, p2.getAffineYCoord());
        return digestDoFinal();
    }

    private byte[] S2(Digest digest2, ECPoint u, byte[] inner) {
        digest2.update((byte) 3);
        addFieldElement(digest2, u.getAffineYCoord());
        digest2.update(inner, 0, inner.length);
        return digestDoFinal();
    }

    private byte[] getZ(Digest digest2, byte[] userID2, ECPoint pubPoint) {
        addUserID(digest2, userID2);
        addFieldElement(digest2, this.ecParams.getCurve().getA());
        addFieldElement(digest2, this.ecParams.getCurve().getB());
        addFieldElement(digest2, this.ecParams.getG().getAffineXCoord());
        addFieldElement(digest2, this.ecParams.getG().getAffineYCoord());
        addFieldElement(digest2, pubPoint.getAffineXCoord());
        addFieldElement(digest2, pubPoint.getAffineYCoord());
        return digestDoFinal();
    }

    private void addUserID(Digest digest2, byte[] userID2) {
        int len = userID2.length * 8;
        digest2.update((byte) (len >>> 8));
        digest2.update((byte) len);
        digest2.update(userID2, 0, userID2.length);
    }

    private void addFieldElement(Digest digest2, ECFieldElement v) {
        byte[] p = v.getEncoded();
        digest2.update(p, 0, p.length);
    }

    private byte[] digestDoFinal() {
        byte[] result = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(result, 0);
        return result;
    }
}
