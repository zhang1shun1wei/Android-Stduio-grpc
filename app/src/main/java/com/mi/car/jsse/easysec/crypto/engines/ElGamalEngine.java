package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.params.ElGamalKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamalEngine implements AsymmetricBlockCipher {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private int bitSize;
    private boolean forEncryption;
    private ElGamalKeyParameters key;
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public void init(boolean forEncryption2, CipherParameters param) {
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom p = (ParametersWithRandom) param;
            this.key = (ElGamalKeyParameters) p.getParameters();
            this.random = p.getRandom();
        } else {
            this.key = (ElGamalKeyParameters) param;
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }
        this.forEncryption = forEncryption2;
        this.bitSize = this.key.getParameters().getP().bitLength();
        if (forEncryption2) {
            if (!(this.key instanceof ElGamalPublicKeyParameters)) {
                throw new IllegalArgumentException("ElGamalPublicKeyParameters are required for encryption.");
            }
        } else if (!(this.key instanceof ElGamalPrivateKeyParameters)) {
            throw new IllegalArgumentException("ElGamalPrivateKeyParameters are required for decryption.");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        if (this.forEncryption) {
            return (this.bitSize - 1) / 8;
        }
        return ((this.bitSize + 7) / 8) * 2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        if (this.forEncryption) {
            return ((this.bitSize + 7) / 8) * 2;
        }
        return (this.bitSize - 1) / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] in, int inOff, int inLen) {
        int maxLength;
        byte[] block;
        if (this.key == null) {
            throw new IllegalStateException("ElGamal engine not initialised");
        }
        if (this.forEncryption) {
            maxLength = ((this.bitSize - 1) + 7) / 8;
        } else {
            maxLength = getInputBlockSize();
        }
        if (inLen > maxLength) {
            throw new DataLengthException("input too large for ElGamal cipher.\n");
        }
        BigInteger p = this.key.getParameters().getP();
        if (this.key instanceof ElGamalPrivateKeyParameters) {
            byte[] in1 = new byte[(inLen / 2)];
            byte[] in2 = new byte[(inLen / 2)];
            System.arraycopy(in, inOff, in1, 0, in1.length);
            System.arraycopy(in, in1.length + inOff, in2, 0, in2.length);
            BigInteger gamma = new BigInteger(1, in1);
            return BigIntegers.asUnsignedByteArray(gamma.modPow(p.subtract(ONE).subtract(((ElGamalPrivateKeyParameters) this.key).getX()), p).multiply(new BigInteger(1, in2)).mod(p));
        }
        if (inOff == 0 && inLen == in.length) {
            block = in;
        } else {
            block = new byte[inLen];
            System.arraycopy(in, inOff, block, 0, inLen);
        }
        BigInteger input = new BigInteger(1, block);
        if (input.compareTo(p) >= 0) {
            throw new DataLengthException("input too large for ElGamal cipher.\n");
        }
        ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters) this.key;
        int pBitLength = p.bitLength();
        BigInteger k = BigIntegers.createRandomBigInteger(pBitLength, this.random);
        while (true) {
            if (!k.equals(ZERO) && k.compareTo(p.subtract(TWO)) <= 0) {
                break;
            }
            k = BigIntegers.createRandomBigInteger(pBitLength, this.random);
        }
        BigInteger gamma2 = this.key.getParameters().getG().modPow(k, p);
        BigInteger phi = input.multiply(pub.getY().modPow(k, p)).mod(p);
        byte[] out1 = gamma2.toByteArray();
        byte[] out2 = phi.toByteArray();
        byte[] output = new byte[getOutputBlockSize()];
        if (out1.length > output.length / 2) {
            System.arraycopy(out1, 1, output, (output.length / 2) - (out1.length - 1), out1.length - 1);
        } else {
            System.arraycopy(out1, 0, output, (output.length / 2) - out1.length, out1.length);
        }
        if (out2.length > output.length / 2) {
            System.arraycopy(out2, 1, output, output.length - (out2.length - 1), out2.length - 1);
            return output;
        }
        System.arraycopy(out2, 0, output, output.length - out2.length, out2.length);
        return output;
    }
}
