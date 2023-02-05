package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.params.CramerShoupKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.CramerShoupPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.CramerShoupPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.Strings;
import java.math.BigInteger;
import java.security.SecureRandom;

public class CramerShoupCoreEngine {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private boolean forEncryption;
    private CramerShoupKeyParameters key;
    private byte[] label = null;
    private SecureRandom random;

    public void init(boolean forEncryption2, CipherParameters param, String label2) {
        init(forEncryption2, param);
        this.label = Strings.toUTF8ByteArray(label2);
    }

    public void init(boolean forEncryption2, CipherParameters param) {
        SecureRandom providedRandom = null;
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.key = (CramerShoupKeyParameters) rParam.getParameters();
            providedRandom = rParam.getRandom();
        } else {
            this.key = (CramerShoupKeyParameters) param;
        }
        this.random = initSecureRandom(forEncryption2, providedRandom);
        this.forEncryption = forEncryption2;
    }

    public int getInputBlockSize() {
        int bitSize = this.key.getParameters().getP().bitLength();
        if (this.forEncryption) {
            return ((bitSize + 7) / 8) - 1;
        }
        return (bitSize + 7) / 8;
    }

    public int getOutputBlockSize() {
        int bitSize = this.key.getParameters().getP().bitLength();
        if (this.forEncryption) {
            return (bitSize + 7) / 8;
        }
        return ((bitSize + 7) / 8) - 1;
    }

    public BigInteger convertInput(byte[] in, int inOff, int inLen) {
        byte[] block;
        if (inLen > getInputBlockSize() + 1) {
            throw new DataLengthException("input too large for Cramer Shoup cipher.");
        } else if (inLen != getInputBlockSize() + 1 || !this.forEncryption) {
            if (inOff == 0 && inLen == in.length) {
                block = in;
            } else {
                block = new byte[inLen];
                System.arraycopy(in, inOff, block, 0, inLen);
            }
            BigInteger res = new BigInteger(1, block);
            if (res.compareTo(this.key.getParameters().getP()) < 0) {
                return res;
            }
            throw new DataLengthException("input too large for Cramer Shoup cipher.");
        } else {
            throw new DataLengthException("input too large for Cramer Shoup cipher.");
        }
    }

    public byte[] convertOutput(BigInteger result) {
        byte[] output = result.toByteArray();
        if (!this.forEncryption) {
            if (output[0] == 0 && output.length > getOutputBlockSize()) {
                byte[] tmp = new byte[(output.length - 1)];
                System.arraycopy(output, 1, tmp, 0, tmp.length);
                return tmp;
            } else if (output.length < getOutputBlockSize()) {
                byte[] tmp2 = new byte[getOutputBlockSize()];
                System.arraycopy(output, 0, tmp2, tmp2.length - output.length, output.length);
                return tmp2;
            }
        } else if (output[0] == 0) {
            byte[] tmp3 = new byte[(output.length - 1)];
            System.arraycopy(output, 1, tmp3, 0, tmp3.length);
            return tmp3;
        }
        return output;
    }

    public CramerShoupCiphertext encryptBlock(BigInteger input) {
        CramerShoupCiphertext result = null;
        if (!this.key.isPrivate() && this.forEncryption && (this.key instanceof CramerShoupPublicKeyParameters)) {
            CramerShoupPublicKeyParameters pk = (CramerShoupPublicKeyParameters) this.key;
            BigInteger p = pk.getParameters().getP();
            BigInteger g1 = pk.getParameters().getG1();
            BigInteger g2 = pk.getParameters().getG2();
            BigInteger h = pk.getH();
            if (!isValidMessage(input, p)) {
                return null;
            }
            BigInteger r = generateRandomElement(p, this.random);
            BigInteger u1 = g1.modPow(r, p);
            BigInteger u2 = g2.modPow(r, p);
            BigInteger e = h.modPow(r, p).multiply(input).mod(p);
            Digest digest = pk.getParameters().getH();
            byte[] u1Bytes = u1.toByteArray();
            digest.update(u1Bytes, 0, u1Bytes.length);
            byte[] u2Bytes = u2.toByteArray();
            digest.update(u2Bytes, 0, u2Bytes.length);
            byte[] eBytes = e.toByteArray();
            digest.update(eBytes, 0, eBytes.length);
            if (this.label != null) {
                byte[] lBytes = this.label;
                digest.update(lBytes, 0, lBytes.length);
            }
            byte[] out = new byte[digest.getDigestSize()];
            digest.doFinal(out, 0);
            result = new CramerShoupCiphertext(u1, u2, e, pk.getC().modPow(r, p).multiply(pk.getD().modPow(r.multiply(new BigInteger(1, out)), p)).mod(p));
        }
        return result;
    }

    public BigInteger decryptBlock(CramerShoupCiphertext input) throws CramerShoupCiphertextException {
        if (!this.key.isPrivate() || this.forEncryption || !(this.key instanceof CramerShoupPrivateKeyParameters)) {
            return null;
        }
        CramerShoupPrivateKeyParameters sk = (CramerShoupPrivateKeyParameters) this.key;
        BigInteger p = sk.getParameters().getP();
        Digest digest = sk.getParameters().getH();
        byte[] u1Bytes = input.getU1().toByteArray();
        digest.update(u1Bytes, 0, u1Bytes.length);
        byte[] u2Bytes = input.getU2().toByteArray();
        digest.update(u2Bytes, 0, u2Bytes.length);
        byte[] eBytes = input.getE().toByteArray();
        digest.update(eBytes, 0, eBytes.length);
        if (this.label != null) {
            byte[] lBytes = this.label;
            digest.update(lBytes, 0, lBytes.length);
        }
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        BigInteger a = new BigInteger(1, out);
        if (input.v.equals(input.u1.modPow(sk.getX1().add(sk.getY1().multiply(a)), p).multiply(input.u2.modPow(sk.getX2().add(sk.getY2().multiply(a)), p)).mod(p))) {
            return input.e.multiply(input.u1.modPow(sk.getZ(), p).modInverse(p)).mod(p);
        }
        throw new CramerShoupCiphertextException("Sorry, that ciphertext is not correct");
    }

    private BigInteger generateRandomElement(BigInteger p, SecureRandom random2) {
        return BigIntegers.createRandomInRange(ONE, p.subtract(ONE), random2);
    }

    private boolean isValidMessage(BigInteger m, BigInteger p) {
        return m.compareTo(p) < 0;
    }

    /* access modifiers changed from: protected */
    public SecureRandom initSecureRandom(boolean needed, SecureRandom provided) {
        if (needed) {
            return CryptoServicesRegistrar.getSecureRandom(provided);
        }
        return null;
    }

    public static class CramerShoupCiphertextException extends Exception {
        private static final long serialVersionUID = -6360977166495345076L;

        public CramerShoupCiphertextException(String msg) {
            super(msg);
        }
    }
}
