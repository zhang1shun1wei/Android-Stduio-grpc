package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.math.Primes;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public final class IntegerFunctions {
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final int[] SMALL_PRIMES = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41};
    private static final long SMALL_PRIME_PRODUCT = 152125131763605L;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final int[] jacobiTable = {0, 1, 0, -1, 0, -1, 0, 1};
    private static SecureRandom sr = null;

    private IntegerFunctions() {
    }

    public static int jacobi(BigInteger A, BigInteger B) {
        int i = 1;
        long k = 1;
        if (B.equals(ZERO)) {
            if (!A.abs().equals(ONE)) {
                i = 0;
            }
            return i;
        } else if (!A.testBit(0) && !B.testBit(0)) {
            return 0;
        } else {
            BigInteger a = A;
            BigInteger b = B;
            if (b.signum() == -1) {
                b = b.negate();
                if (a.signum() == -1) {
                    k = -1;
                }
            }
            BigInteger v = ZERO;
            while (!b.testBit(0)) {
                v = v.add(ONE);
                b = b.divide(TWO);
            }
            if (v.testBit(0)) {
                k *= (long) jacobiTable[a.intValue() & 7];
            }
            if (a.signum() < 0) {
                if (b.testBit(1)) {
                    k = -k;
                }
                a = a.negate();
            }
            while (a.signum() != 0) {
                BigInteger v2 = ZERO;
                while (!a.testBit(0)) {
                    v2 = v2.add(ONE);
                    a = a.divide(TWO);
                }
                if (v2.testBit(0)) {
                    k *= (long) jacobiTable[b.intValue() & 7];
                }
                if (a.compareTo(b) < 0) {
                    a = b;
                    b = a;
                    if (a.testBit(1) && b.testBit(1)) {
                        k = -k;
                    }
                }
                a = a.subtract(b);
            }
            if (b.equals(ONE)) {
                return (int) k;
            }
            return 0;
        }
    }

    public static int gcd(int u, int v) {
        return BigInteger.valueOf((long) u).gcd(BigInteger.valueOf((long) v)).intValue();
    }

    public static int[] extGCD(int a, int b) {
        BigInteger[] bresult = extgcd(BigInteger.valueOf((long) a), BigInteger.valueOf((long) b));
        return new int[]{bresult[0].intValue(), bresult[1].intValue(), bresult[2].intValue()};
    }

    public static BigInteger divideAndRound(BigInteger a, BigInteger b) {
        if (a.signum() < 0) {
            return divideAndRound(a.negate(), b).negate();
        }
        if (b.signum() < 0) {
            return divideAndRound(a, b.negate()).negate();
        }
        return a.shiftLeft(1).add(b).divide(b.shiftLeft(1));
    }

    public static BigInteger[] divideAndRound(BigInteger[] a, BigInteger b) {
        BigInteger[] out = new BigInteger[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = divideAndRound(a[i], b);
        }
        return out;
    }

    public static int ceilLog(BigInteger a) {
        int result = 0;
        for (BigInteger p = ONE; p.compareTo(a) < 0; p = p.shiftLeft(1)) {
            result++;
        }
        return result;
    }

    public static int ceilLog(int a) {
        int log = 0;
        int i = 1;
        while (i < a) {
            i <<= 1;
            log++;
        }
        return log;
    }

    public static int ceilLog256(int n) {
        int m;
        if (n == 0) {
            return 1;
        }
        if (n < 0) {
            m = -n;
        } else {
            m = n;
        }
        int d = 0;
        while (m > 0) {
            d++;
            m >>>= 8;
        }
        return d;
    }

    public static int ceilLog256(long n) {
        long m;
        if (n == 0) {
            return 1;
        }
        if (n < 0) {
            m = -n;
        } else {
            m = n;
        }
        int d = 0;
        while (m > 0) {
            d++;
            m >>>= 8;
        }
        return d;
    }

    public static int floorLog(BigInteger a) {
        int result = -1;
        for (BigInteger p = ONE; p.compareTo(a) <= 0; p = p.shiftLeft(1)) {
            result++;
        }
        return result;
    }

    public static int floorLog(int a) {
        if (a <= 0) {
            return -1;
        }
        int p = a >>> 1;
        int h = 0;
        while (p > 0) {
            p >>>= 1;
            h++;
        }
        return h;
    }

    public static int maxPower(int a) {
        int h = 0;
        if (a != 0) {
            for (int p = 1; (a & p) == 0; p <<= 1) {
                h++;
            }
        }
        return h;
    }

    public static int bitCount(int a) {
        int h = 0;
        while (a != 0) {
            h += a & 1;
            a >>>= 1;
        }
        return h;
    }

    public static int order(int g, int p) {
        int b = g % p;
        int j = 1;
        if (b == 0) {
            throw new IllegalArgumentException(g + " is not an element of Z/(" + p + "Z)^*; it is not meaningful to compute its order.");
        }
        while (b != 1) {
            b = (b * g) % p;
            if (b < 0) {
                b += p;
            }
            j++;
        }
        return j;
    }

    public static BigInteger reduceInto(BigInteger n, BigInteger begin, BigInteger end) {
        return n.subtract(begin).mod(end.subtract(begin)).add(begin);
    }

    public static int pow(int a, int e) {
        int result = 1;
        while (e > 0) {
            if ((e & 1) == 1) {
                result *= a;
            }
            a *= a;
            e >>>= 1;
        }
        return result;
    }

    public static long pow(long a, int e) {
        long result = 1;
        while (e > 0) {
            if ((e & 1) == 1) {
                result *= a;
            }
            a *= a;
            e >>>= 1;
        }
        return result;
    }

    public static int modPow(int a, int e, int n) {
        if (n <= 0 || n * n > Integer.MAX_VALUE || e < 0) {
            return 0;
        }
        int result = 1;
        int a2 = ((a % n) + n) % n;
        while (e > 0) {
            if ((e & 1) == 1) {
                result = (result * a2) % n;
            }
            a2 = (a2 * a2) % n;
            e >>>= 1;
        }
        return result;
    }

    public static BigInteger[] extgcd(BigInteger a, BigInteger b) {
        BigInteger u = ONE;
        BigInteger v = ZERO;
        BigInteger d = a;
        if (b.signum() != 0) {
            BigInteger v1 = ZERO;
            BigInteger v3 = b;
            while (v3.signum() != 0) {
                BigInteger[] tmp = d.divideAndRemainder(v3);
                BigInteger q = tmp[0];
                BigInteger t3 = tmp[1];
                BigInteger t1 = u.subtract(q.multiply(v1));
                u = v1;
                d = v3;
                v1 = t1;
                v3 = t3;
            }
            v = d.subtract(a.multiply(u)).divide(b);
        }
        return new BigInteger[]{d, u, v};
    }

    public static BigInteger leastCommonMultiple(BigInteger[] numbers) {
        int n = numbers.length;
        BigInteger result = numbers[0];
        for (int i = 1; i < n; i++) {
            result = result.multiply(numbers[i]).divide(result.gcd(numbers[i]));
        }
        return result;
    }

    public static long mod(long a, long m) {
        long result = a % m;
        if (result < 0) {
            return result + m;
        }
        return result;
    }

    public static int modInverse(int a, int mod) {
        return BigInteger.valueOf((long) a).modInverse(BigInteger.valueOf((long) mod)).intValue();
    }

    public static long modInverse(long a, long mod) {
        return BigInteger.valueOf(a).modInverse(BigInteger.valueOf(mod)).longValue();
    }

    public static int isPower(int a, int p) {
        if (a <= 0) {
            return -1;
        }
        int n = 0;
        int d = a;
        while (d > 1) {
            if (d % p != 0) {
                return -1;
            }
            d /= p;
            n++;
        }
        return n;
    }

    public static int leastDiv(int a) {
        if (a < 0) {
            a = -a;
        }
        if (a == 0) {
            return 1;
        }
        if ((a & 1) == 0) {
            return 2;
        }
        for (int p = 3; p <= a / p; p += 2) {
            if (a % p == 0) {
                return p;
            }
        }
        return a;
    }

    public static boolean isPrime(int n) {
        if (n < 2) {
            return false;
        }
        if (n == 2) {
            return true;
        }
        if ((n & 1) == 0) {
            return false;
        }
        if (n < 42) {
            for (int i = 0; i < SMALL_PRIMES.length; i++) {
                if (n == SMALL_PRIMES[i]) {
                    return true;
                }
            }
        }
        if (n % 3 == 0 || n % 5 == 0 || n % 7 == 0 || n % 11 == 0 || n % 13 == 0 || n % 17 == 0 || n % 19 == 0 || n % 23 == 0 || n % 29 == 0 || n % 31 == 0 || n % 37 == 0 || n % 41 == 0) {
            return false;
        }
        return BigInteger.valueOf((long) n).isProbablePrime(20);
    }

    public static boolean passesSmallPrimeTest(BigInteger candidate) {
        int[] smallPrime;
        for (int i : new int[]{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, Primes.SMALL_FACTOR_LIMIT, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499}) {
            if (candidate.mod(BigInteger.valueOf((long) i)).equals(ZERO)) {
                return false;
            }
        }
        return true;
    }

    public static int nextSmallerPrime(int n) {
        int n2;
        if (n <= 2) {
            return 1;
        }
        if (n == 3) {
            return 2;
        }
        if ((n & 1) == 0) {
            n2 = n - 1;
        } else {
            n2 = n - 2;
        }
        while (n2 > 3 && !isPrime(n2)) {
            n2 -= 2;
        }
        return n2;
    }

    public static BigInteger nextProbablePrime(BigInteger n, int certainty) {
        if (n.signum() < 0 || n.signum() == 0 || n.equals(ONE)) {
            return TWO;
        }
        BigInteger result = n.add(ONE);
        if (!result.testBit(0)) {
            result = result.add(ONE);
        }
        while (true) {
            if (result.bitLength() > 6) {
                long r = result.remainder(BigInteger.valueOf(SMALL_PRIME_PRODUCT)).longValue();
                if (r % 3 == 0 || r % 5 == 0 || r % 7 == 0 || r % 11 == 0 || r % 13 == 0 || r % 17 == 0 || r % 19 == 0 || r % 23 == 0 || r % 29 == 0 || r % 31 == 0 || r % 37 == 0 || r % 41 == 0) {
                    result = result.add(TWO);
                }
            }
            if (result.bitLength() < 4 || result.isProbablePrime(certainty)) {
                return result;
            }
            result = result.add(TWO);
        }
    }

    public static BigInteger nextProbablePrime(BigInteger n) {
        return nextProbablePrime(n, 20);
    }

    public static BigInteger nextPrime(long n) {
        boolean found = false;
        long result = 0;
        if (n <= 1) {
            return BigInteger.valueOf(2);
        }
        if (n == 2) {
            return BigInteger.valueOf(3);
        }
        for (long i = 1 + n + (1 & n); i <= (n << 1) && !found; i += 2) {
            for (long j = 3; j <= (i >> 1) && !found; j += 2) {
                if (i % j == 0) {
                    found = true;
                }
            }
            if (found) {
                found = false;
            } else {
                result = i;
                found = true;
            }
        }
        return BigInteger.valueOf(result);
    }

    public static BigInteger binomial(int n, int t) {
        BigInteger result = ONE;
        if (n != 0) {
            if (t > (n >>> 1)) {
                t = n - t;
            }
            for (int i = 1; i <= t; i++) {
                result = result.multiply(BigInteger.valueOf((long) (n - (i - 1)))).divide(BigInteger.valueOf((long) i));
            }
            return result;
        } else if (t == 0) {
            return result;
        } else {
            return ZERO;
        }
    }

    public static BigInteger randomize(BigInteger upperBound) {
        if (sr == null) {
            sr = CryptoServicesRegistrar.getSecureRandom();
        }
        return randomize(upperBound, sr);
    }

    public static BigInteger randomize(BigInteger upperBound, SecureRandom prng) {
        int blen = upperBound.bitLength();
        BigInteger randomNum = BigInteger.valueOf(0);
        if (prng == null) {
            prng = sr != null ? sr : CryptoServicesRegistrar.getSecureRandom();
        }
        for (int i = 0; i < 20; i++) {
            randomNum = BigIntegers.createRandomBigInteger(blen, prng);
            if (randomNum.compareTo(upperBound) < 0) {
                return randomNum;
            }
        }
        return randomNum.mod(upperBound);
    }

    public static BigInteger squareRoot(BigInteger a) {
        int i;
        int i2;
        if (a.compareTo(ZERO) < 0) {
            throw new ArithmeticException("cannot extract root of negative number" + a + ".");
        }
        int bl = a.bitLength();
        BigInteger result = ZERO;
        BigInteger remainder = ZERO;
        if ((bl & 1) != 0) {
            result = result.add(ONE);
            bl--;
        }
        while (bl > 0) {
            BigInteger remainder2 = remainder.multiply(FOUR);
            int bl2 = bl - 1;
            if (a.testBit(bl2)) {
                i = 2;
            } else {
                i = 0;
            }
            bl = bl2 - 1;
            if (a.testBit(bl)) {
                i2 = 1;
            } else {
                i2 = 0;
            }
            remainder = remainder2.add(BigInteger.valueOf((long) (i + i2)));
            BigInteger b = result.multiply(FOUR).add(ONE);
            result = result.multiply(TWO);
            if (remainder.compareTo(b) != -1) {
                result = result.add(ONE);
                remainder = remainder.subtract(b);
            }
        }
        return result;
    }

    public static float intRoot(int base, int root) {
        float gNew = (float) (base / root);
        float gOld = 0.0f;
        int counter = 0;
        while (((double) Math.abs(gOld - gNew)) > 1.0E-4d) {
            float gPow = floatPow(gNew, root);
            while (Float.isInfinite(gPow)) {
                gNew = (gNew + gOld) / 2.0f;
                gPow = floatPow(gNew, root);
            }
            counter++;
            gOld = gNew;
            gNew = gOld - ((gPow - ((float) base)) / (((float) root) * floatPow(gOld, root - 1)));
        }
        return gNew;
    }

    public static float floatPow(float f, int i) {
        float g = 1.0f;
        while (i > 0) {
            g *= f;
            i--;
        }
        return g;
    }

    public static double log(double x) {
        if (x > 0.0d && x < 1.0d) {
            return -log(1.0d / x);
        }
        int tmp = 0;
        double tmp2 = 1.0d;
        double d = x;
        while (d > 2.0d) {
            d /= 2.0d;
            tmp++;
            tmp2 *= 2.0d;
        }
        return ((double) tmp) + logBKM(x / tmp2);
    }

    public static double log(long x) {
        int tmp = floorLog(BigInteger.valueOf(x));
        return ((double) tmp) + logBKM(((double) x) / ((double) ((long) (1 << tmp))));
    }

    private static double logBKM(double arg) {
        double[] ae = {1.0d, 0.5849625007211562d, 0.32192809488736235d, 0.16992500144231237d, 0.0874628412503394d, 0.044394119358453436d, 0.02236781302845451d, 0.01122725542325412d, 0.005624549193878107d, 0.0028150156070540383d, 0.0014081943928083889d, 7.042690112466433E-4d, 3.5217748030102726E-4d, 1.7609948644250602E-4d, 8.80524301221769E-5d, 4.4026886827316716E-5d, 2.2013611360340496E-5d, 1.1006847667481442E-5d, 5.503434330648604E-6d, 2.751719789561283E-6d, 1.375860550841138E-6d, 6.879304394358497E-7d, 3.4396526072176454E-7d, 1.7198264061184464E-7d, 8.599132286866321E-8d, 4.299566207501687E-8d, 2.1497831197679756E-8d, 1.0748915638882709E-8d, 5.374457829452062E-9d, 2.687228917228708E-9d, 1.3436144592400231E-9d, 6.718072297764289E-10d, 3.3590361492731876E-10d, 1.6795180747343547E-10d, 8.397590373916176E-11d, 4.1987951870191886E-11d, 2.0993975935248694E-11d, 1.0496987967662534E-11d, 5.2484939838408146E-12d, 2.624246991922794E-12d, 1.3121234959619935E-12d, 6.56061747981146E-13d, 3.2803087399061026E-13d, 1.6401543699531447E-13d, 8.200771849765956E-14d, 4.1003859248830365E-14d, 2.0501929624415328E-14d, 1.02509648122077E-14d, 5.1254824061038595E-15d, 2.5627412030519317E-15d, 1.2813706015259665E-15d, 6.406853007629834E-16d, 3.203426503814917E-16d, 1.6017132519074588E-16d, 8.008566259537294E-17d, 4.004283129768647E-17d, 2.0021415648843235E-17d, 1.0010707824421618E-17d, 5.005353912210809E-18d, 2.5026769561054044E-18d, 1.2513384780527022E-18d, 6.256692390263511E-19d, 3.1283461951317555E-19d, 1.5641730975658778E-19d, 7.820865487829389E-20d, 3.9104327439146944E-20d, 1.9552163719573472E-20d, 9.776081859786736E-21d, 4.888040929893368E-21d, 2.444020464946684E-21d, 1.222010232473342E-21d, 6.11005116236671E-22d, 3.055025581183355E-22d, 1.5275127905916775E-22d, 7.637563952958387E-23d, 3.818781976479194E-23d, 1.909390988239597E-23d, 9.546954941197984E-24d, 4.773477470598992E-24d, 2.386738735299496E-24d, 1.193369367649748E-24d, 5.96684683824874E-25d, 2.98342341912437E-25d, 1.491711709562185E-25d, 7.458558547810925E-26d, 3.7292792739054626E-26d, 1.8646396369527313E-26d, 9.323198184763657E-27d, 4.661599092381828E-27d, 2.330799546190914E-27d, 1.165399773095457E-27d, 5.826998865477285E-28d, 2.9134994327386427E-28d, 1.4567497163693213E-28d, 7.283748581846607E-29d, 3.6418742909233034E-29d, 1.8209371454616517E-29d, 9.104685727308258E-30d, 4.552342863654129E-30d, 2.2761714318270646E-30d};
        double x = 1.0d;
        double y = 0.0d;
        double s = 1.0d;
        for (int k = 0; k < 53; k++) {
            double z = x + (x * s);
            if (z <= arg) {
                x = z;
                y += ae[k];
            }
            s *= 0.5d;
        }
        return y;
    }

    public static boolean isIncreasing(int[] a) {
        for (int i = 1; i < a.length; i++) {
            if (a[i - 1] >= a[i]) {
                return false;
            }
        }
        return true;
    }

    public static byte[] integerToOctets(BigInteger val) {
        byte[] valBytes = val.abs().toByteArray();
        if ((val.bitLength() & 7) != 0) {
            return valBytes;
        }
        byte[] tmp = new byte[(val.bitLength() >> 3)];
        System.arraycopy(valBytes, 1, tmp, 0, tmp.length);
        return tmp;
    }

    public static BigInteger octetsToInteger(byte[] data, int offset, int length) {
        byte[] val = new byte[(length + 1)];
        val[0] = 0;
        System.arraycopy(data, offset, val, 1, length);
        return new BigInteger(val);
    }

    public static BigInteger octetsToInteger(byte[] data) {
        return octetsToInteger(data, 0, data.length);
    }
}
