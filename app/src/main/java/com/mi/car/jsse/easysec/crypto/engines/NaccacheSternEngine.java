package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.params.NaccacheSternKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.NaccacheSternPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;
import java.util.Vector;

public class NaccacheSternEngine implements AsymmetricBlockCipher {
    private static BigInteger ONE = BigInteger.valueOf(1);
    private static BigInteger ZERO = BigInteger.valueOf(0);
    private boolean debug = false;
    private boolean forEncryption;
    private NaccacheSternKeyParameters key;
    private Vector[] lookup = null;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public void init(boolean forEncryption2, CipherParameters param) {
        this.forEncryption = forEncryption2;
        if (param instanceof ParametersWithRandom) {
            param = ((ParametersWithRandom) param).getParameters();
        }
        this.key = (NaccacheSternKeyParameters) param;
        if (!this.forEncryption) {
            if (this.debug) {
                System.out.println("Constructing lookup Array");
            }
            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters) this.key;
            Vector primes = priv.getSmallPrimes();
            this.lookup = new Vector[primes.size()];
            for (int i = 0; i < primes.size(); i++) {
                BigInteger actualPrime = (BigInteger) primes.elementAt(i);
                int actualPrimeValue = actualPrime.intValue();
                this.lookup[i] = new Vector();
                this.lookup[i].addElement(ONE);
                if (this.debug) {
                    System.out.println("Constructing lookup ArrayList for " + actualPrimeValue);
                }
                BigInteger accJ = ZERO;
                for (int j = 1; j < actualPrimeValue; j++) {
                    accJ = accJ.add(priv.getPhi_n());
                    this.lookup[i].addElement(priv.getG().modPow(accJ.divide(actualPrime), priv.getModulus()));
                }
            }
        }
    }

    public void setDebug(boolean debug2) {
        this.debug = debug2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        if (this.forEncryption) {
            return ((this.key.getLowerSigmaBound() + 7) / 8) - 1;
        }
        return this.key.getModulus().toByteArray().length;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        if (this.forEncryption) {
            return this.key.getModulus().toByteArray().length;
        }
        return ((this.key.getLowerSigmaBound() + 7) / 8) - 1;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] in, int inOff, int len) throws InvalidCipherTextException {
        byte[] block;
        if (this.key == null) {
            throw new IllegalStateException("NaccacheStern engine not initialised");
        } else if (len > getInputBlockSize() + 1) {
            throw new DataLengthException("input too large for Naccache-Stern cipher.\n");
        } else if (this.forEncryption || len >= getInputBlockSize()) {
            if (inOff == 0 && len == in.length) {
                block = in;
            } else {
                block = new byte[len];
                System.arraycopy(in, inOff, block, 0, len);
            }
            BigInteger input = new BigInteger(1, block);
            if (this.debug) {
                System.out.println("input as BigInteger: " + input);
            }
            if (this.forEncryption) {
                return encrypt(input);
            }
            Vector plain = new Vector();
            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters) this.key;
            Vector primes = priv.getSmallPrimes();
            for (int i = 0; i < primes.size(); i++) {
                BigInteger exp = input.modPow(priv.getPhi_n().divide((BigInteger) primes.elementAt(i)), priv.getModulus());
                Vector al = this.lookup[i];
                if (this.lookup[i].size() != ((BigInteger) primes.elementAt(i)).intValue()) {
                    if (this.debug) {
                        System.out.println("Prime is " + primes.elementAt(i) + ", lookup table has size " + al.size());
                    }
                    throw new InvalidCipherTextException("Error in lookup Array for " + ((BigInteger) primes.elementAt(i)).intValue() + ": Size mismatch. Expected ArrayList with length " + ((BigInteger) primes.elementAt(i)).intValue() + " but found ArrayList of length " + this.lookup[i].size());
                }
                int lookedup = al.indexOf(exp);
                if (lookedup == -1) {
                    if (this.debug) {
                        System.out.println("Actual prime is " + primes.elementAt(i));
                        System.out.println("Decrypted value is " + exp);
                        System.out.println("LookupList for " + primes.elementAt(i) + " with size " + this.lookup[i].size() + " is: ");
                        for (int j = 0; j < this.lookup[i].size(); j++) {
                            System.out.println(this.lookup[i].elementAt(j));
                        }
                    }
                    throw new InvalidCipherTextException("Lookup failed");
                }
                plain.addElement(BigInteger.valueOf((long) lookedup));
            }
            return chineseRemainder(plain, primes).toByteArray();
        } else {
            throw new InvalidCipherTextException("BlockLength does not match modulus for Naccache-Stern cipher.\n");
        }
    }

    public byte[] encrypt(BigInteger plain) {
        byte[] output = this.key.getModulus().toByteArray();
        Arrays.fill(output, (byte) 0);
        byte[] tmp = this.key.getG().modPow(plain, this.key.getModulus()).toByteArray();
        System.arraycopy(tmp, 0, output, output.length - tmp.length, tmp.length);
        if (this.debug) {
            System.out.println("Encrypted value is:  " + new BigInteger(output));
        }
        return output;
    }

    public byte[] addCryptedBlocks(byte[] block1, byte[] block2) throws InvalidCipherTextException {
        if (this.forEncryption) {
            if (block1.length > getOutputBlockSize() || block2.length > getOutputBlockSize()) {
                throw new InvalidCipherTextException("BlockLength too large for simple addition.\n");
            }
        } else if (block1.length > getInputBlockSize() || block2.length > getInputBlockSize()) {
            throw new InvalidCipherTextException("BlockLength too large for simple addition.\n");
        }
        BigInteger m1Crypt = new BigInteger(1, block1);
        BigInteger m2Crypt = new BigInteger(1, block2);
        BigInteger m1m2Crypt = m1Crypt.multiply(m2Crypt).mod(this.key.getModulus());
        if (this.debug) {
            System.out.println("c(m1) as BigInteger:....... " + m1Crypt);
            System.out.println("c(m2) as BigInteger:....... " + m2Crypt);
            System.out.println("c(m1)*c(m2)%n = c(m1+m2)%n: " + m1m2Crypt);
        }
        byte[] output = this.key.getModulus().toByteArray();
        Arrays.fill(output, (byte) 0);
        System.arraycopy(m1m2Crypt.toByteArray(), 0, output, output.length - m1m2Crypt.toByteArray().length, m1m2Crypt.toByteArray().length);
        return output;
    }

    public byte[] processData(byte[] data) throws InvalidCipherTextException {
        byte[] tmp;
        if (this.debug) {
            System.out.println();
        }
        if (data.length > getInputBlockSize()) {
            int inBlocksize = getInputBlockSize();
            int outBlocksize = getOutputBlockSize();
            if (this.debug) {
                System.out.println("Input blocksize is:  " + inBlocksize + " bytes");
                System.out.println("Output blocksize is: " + outBlocksize + " bytes");
                System.out.println("Data has length:.... " + data.length + " bytes");
            }
            int datapos = 0;
            int retpos = 0;
            byte[] retval = new byte[(((data.length / inBlocksize) + 1) * outBlocksize)];
            while (datapos < data.length) {
                if (datapos + inBlocksize < data.length) {
                    tmp = processBlock(data, datapos, inBlocksize);
                    datapos += inBlocksize;
                } else {
                    tmp = processBlock(data, datapos, data.length - datapos);
                    datapos += data.length - datapos;
                }
                if (this.debug) {
                    System.out.println("new datapos is " + datapos);
                }
                if (tmp != null) {
                    System.arraycopy(tmp, 0, retval, retpos, tmp.length);
                    retpos += tmp.length;
                } else {
                    if (this.debug) {
                        System.out.println("cipher returned null");
                    }
                    throw new InvalidCipherTextException("cipher returned null");
                }
            }
            byte[] ret = new byte[retpos];
            System.arraycopy(retval, 0, ret, 0, retpos);
            if (!this.debug) {
                return ret;
            }
            System.out.println("returning " + ret.length + " bytes");
            return ret;
        }
        if (this.debug) {
            System.out.println("data size is less then input block size, processing directly");
        }
        return processBlock(data, 0, data.length);
    }

    private static BigInteger chineseRemainder(Vector congruences, Vector primes) {
        BigInteger retval = ZERO;
        BigInteger all = ONE;
        for (int i = 0; i < primes.size(); i++) {
            all = all.multiply((BigInteger) primes.elementAt(i));
        }
        for (int i2 = 0; i2 < primes.size(); i2++) {
            BigInteger a = (BigInteger) primes.elementAt(i2);
            BigInteger b = all.divide(a);
            retval = retval.add(b.multiply(b.modInverse(a)).multiply((BigInteger) congruences.elementAt(i2)));
        }
        return retval.mod(all);
    }
}
