package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.NaccacheSternKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.NaccacheSternKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.NaccacheSternPrivateKeyParameters;
import com.mi.car.jsse.easysec.math.Primes;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;

public class NaccacheSternKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static int[] smallPrimes = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, Primes.SMALL_FACTOR_LIMIT, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557};
    private NaccacheSternKeyGenerationParameters param;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param2) {
        this.param = (NaccacheSternKeyGenerationParameters) param2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger p_;
        BigInteger p;
        BigInteger q_;
        BigInteger q;
        BigInteger g;
        BigInteger g2;
        int strength = this.param.getStrength();
        SecureRandom rand = this.param.getRandom();
        int certainty = this.param.getCertainty();
        boolean debug = this.param.isDebug();
        if (debug) {
            System.out.println("Fetching first " + this.param.getCntSmallPrimes() + " primes.");
        }
        Vector smallPrimes2 = permuteList(findFirstPrimes(this.param.getCntSmallPrimes()), rand);
        BigInteger u = ONE;
        BigInteger v = ONE;
        for (int i = 0; i < smallPrimes2.size() / 2; i++) {
            u = u.multiply((BigInteger) smallPrimes2.elementAt(i));
        }
        for (int i2 = smallPrimes2.size() / 2; i2 < smallPrimes2.size(); i2++) {
            v = v.multiply((BigInteger) smallPrimes2.elementAt(i2));
        }
        BigInteger sigma = u.multiply(v);
        int remainingStrength = (strength - sigma.bitLength()) - 48;
        BigInteger a = generatePrime((remainingStrength / 2) + 1, certainty, rand);
        BigInteger b = generatePrime((remainingStrength / 2) + 1, certainty, rand);
        long tries = 0;
        if (debug) {
            System.out.println("generating p and q");
        }
        BigInteger _2au = a.multiply(u).shiftLeft(1);
        BigInteger _2bv = b.multiply(v).shiftLeft(1);
        while (true) {
            tries++;
            p_ = generatePrime(24, certainty, rand);
            p = p_.multiply(_2au).add(ONE);
            if (p.isProbablePrime(certainty)) {
                while (true) {
                    q_ = generatePrime(24, certainty, rand);
                    if (!p_.equals(q_)) {
                        q = q_.multiply(_2bv).add(ONE);
                        if (q.isProbablePrime(certainty)) {
                            break;
                        }
                    }
                }
                if (!sigma.gcd(p_.multiply(q_)).equals(ONE)) {
                    continue;
                } else if (p.multiply(q).bitLength() >= strength) {
                    break;
                } else if (debug) {
                    System.out.println("key size too small. Should be " + strength + " but is actually " + p.multiply(q).bitLength());
                }
            }
        }
        if (debug) {
            System.out.println("needed " + tries + " tries to generate p and q.");
        }
        BigInteger n = p.multiply(q);
        BigInteger phi_n = p.subtract(ONE).multiply(q.subtract(ONE));
        long tries2 = 0;
        if (debug) {
            System.out.println("generating g");
        }
        while (true) {
            Vector gParts = new Vector();
            for (int ind = 0; ind != smallPrimes2.size(); ind++) {
                BigInteger e = phi_n.divide((BigInteger) smallPrimes2.elementAt(ind));
                do {
                    tries2++;
                    g2 = BigIntegers.createRandomPrime(strength, certainty, rand);
                } while (g2.modPow(e, n).equals(ONE));
                gParts.addElement(g2);
            }
            g = ONE;
            for (int i3 = 0; i3 < smallPrimes2.size(); i3++) {
                g = g.multiply(((BigInteger) gParts.elementAt(i3)).modPow(sigma.divide((BigInteger) smallPrimes2.elementAt(i3)), n)).mod(n);
            }
            boolean divisible = false;
            int i4 = 0;
            while (true) {
                if (i4 >= smallPrimes2.size()) {
                    break;
                } else if (g.modPow(phi_n.divide((BigInteger) smallPrimes2.elementAt(i4)), n).equals(ONE)) {
                    if (debug) {
                        System.out.println("g has order phi(n)/" + smallPrimes2.elementAt(i4) + "\n g: " + g);
                    }
                    divisible = true;
                } else {
                    i4++;
                }
            }
            if (!divisible) {
                if (!g.modPow(phi_n.divide(BigInteger.valueOf(4)), n).equals(ONE)) {
                    if (!g.modPow(phi_n.divide(p_), n).equals(ONE)) {
                        if (!g.modPow(phi_n.divide(q_), n).equals(ONE)) {
                            if (!g.modPow(phi_n.divide(a), n).equals(ONE)) {
                                if (!g.modPow(phi_n.divide(b), n).equals(ONE)) {
                                    break;
                                } else if (debug) {
                                    System.out.println("g has order phi(n)/b\n g: " + g);
                                }
                            } else if (debug) {
                                System.out.println("g has order phi(n)/a\n g: " + g);
                            }
                        } else if (debug) {
                            System.out.println("g has order phi(n)/q'\n g: " + g);
                        }
                    } else if (debug) {
                        System.out.println("g has order phi(n)/p'\n g: " + g);
                    }
                } else if (debug) {
                    System.out.println("g has order phi(n)/4\n g:" + g);
                }
            }
        }
        if (debug) {
            System.out.println("needed " + tries2 + " tries to generate g");
            System.out.println();
            System.out.println("found new NaccacheStern cipher variables:");
            System.out.println("smallPrimes: " + smallPrimes2);
            System.out.println("sigma:...... " + sigma + " (" + sigma.bitLength() + " bits)");
            System.out.println("a:.......... " + a);
            System.out.println("b:.......... " + b);
            System.out.println("p':......... " + p_);
            System.out.println("q':......... " + q_);
            System.out.println("p:.......... " + p);
            System.out.println("q:.......... " + q);
            System.out.println("n:.......... " + n);
            System.out.println("phi(n):..... " + phi_n);
            System.out.println("g:.......... " + g);
            System.out.println();
        }
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new NaccacheSternKeyParameters(false, g, n, sigma.bitLength()), (AsymmetricKeyParameter) new NaccacheSternPrivateKeyParameters(g, n, sigma.bitLength(), smallPrimes2, phi_n));
    }

    private static BigInteger generatePrime(int bitLength, int certainty, SecureRandom rand) {
        BigInteger p_ = BigIntegers.createRandomPrime(bitLength, certainty, rand);
        while (p_.bitLength() != bitLength) {
            p_ = BigIntegers.createRandomPrime(bitLength, certainty, rand);
        }
        return p_;
    }

    private static Vector permuteList(Vector arr, SecureRandom rand) {
        Vector retval = new Vector();
        Vector tmp = new Vector();
        for (int i = 0; i < arr.size(); i++) {
            tmp.addElement(arr.elementAt(i));
        }
        retval.addElement(tmp.elementAt(0));
        tmp.removeElementAt(0);
        while (tmp.size() != 0) {
            retval.insertElementAt(tmp.elementAt(0), getInt(rand, retval.size() + 1));
            tmp.removeElementAt(0);
        }
        return retval;
    }

    private static int getInt(SecureRandom rand, int n) {
        int bits;
        int val;
        if (((-n) & n) == n) {
            return (int) ((((long) n) * ((long) (rand.nextInt() & Integer.MAX_VALUE))) >> 31);
        }
        do {
            bits = rand.nextInt() & Integer.MAX_VALUE;
            val = bits % n;
        } while ((bits - val) + (n - 1) < 0);
        return val;
    }

    private static Vector findFirstPrimes(int count) {
        Vector primes = new Vector(count);
        for (int i = 0; i != count; i++) {
            primes.addElement(BigInteger.valueOf((long) smallPrimes[i]));
        }
        return primes;
    }
}
