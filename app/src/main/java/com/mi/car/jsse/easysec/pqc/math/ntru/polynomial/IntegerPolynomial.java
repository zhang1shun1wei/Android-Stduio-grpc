package com.mi.car.jsse.easysec.pqc.math.ntru.polynomial;

import com.mi.car.jsse.easysec.pqc.math.ntru.euclid.BigIntEuclidean;
import com.mi.car.jsse.easysec.pqc.math.ntru.util.ArrayEncoder;
import com.mi.car.jsse.easysec.pqc.math.ntru.util.Util;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;

public class IntegerPolynomial implements Polynomial {
    private static final List BIGINT_PRIMES = new ArrayList();
    private static final int NUM_EQUAL_RESULTANTS = 3;
    private static final int[] PRIMES = {4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973};
    public int[] coeffs;

    static {
        for (int i = 0; i != PRIMES.length; i++) {
            BIGINT_PRIMES.add(BigInteger.valueOf((long) PRIMES[i]));
        }
    }

    public IntegerPolynomial(int N) {
        this.coeffs = new int[N];
    }

    public IntegerPolynomial(int[] coeffs2) {
        this.coeffs = coeffs2;
    }

    public IntegerPolynomial(BigIntPolynomial p) {
        this.coeffs = new int[p.coeffs.length];
        for (int i = 0; i < p.coeffs.length; i++) {
            this.coeffs[i] = p.coeffs[i].intValue();
        }
    }

    public static IntegerPolynomial fromBinary3Sves(byte[] data, int N) {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Sves(data, N));
    }

    public static IntegerPolynomial fromBinary3Tight(byte[] b, int N) {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Tight(b, N));
    }

    public static IntegerPolynomial fromBinary3Tight(InputStream is, int N) throws IOException {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Tight(is, N));
    }

    public static IntegerPolynomial fromBinary(byte[] data, int N, int q) {
        return new IntegerPolynomial(ArrayEncoder.decodeModQ(data, N, q));
    }

    public static IntegerPolynomial fromBinary(InputStream is, int N, int q) throws IOException {
        return new IntegerPolynomial(ArrayEncoder.decodeModQ(is, N, q));
    }

    public byte[] toBinary3Sves() {
        return ArrayEncoder.encodeMod3Sves(this.coeffs);
    }

    public byte[] toBinary3Tight() {
        BigInteger sum = Constants.BIGINT_ZERO;
        for (int i = this.coeffs.length - 1; i >= 0; i--) {
            sum = sum.multiply(BigInteger.valueOf(3)).add(BigInteger.valueOf((long) (this.coeffs[i] + 1)));
        }
        int size = (BigInteger.valueOf(3).pow(this.coeffs.length).bitLength() + 7) / 8;
        byte[] arr = sum.toByteArray();
        if (arr.length < size) {
            byte[] arr2 = new byte[size];
            System.arraycopy(arr, 0, arr2, size - arr.length, arr.length);
            return arr2;
        }
        if (arr.length > size) {
            arr = Arrays.copyOfRange(arr, 1, arr.length);
        }
        return arr;
    }

    public byte[] toBinary(int q) {
        return ArrayEncoder.encodeModQ(this.coeffs, q);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    public IntegerPolynomial mult(IntegerPolynomial poly2) {
        int N = this.coeffs.length;
        if (poly2.coeffs.length != N) {
            throw new IllegalArgumentException("Number of coefficients must be the same");
        }
        IntegerPolynomial c = multRecursive(poly2);
        if (c.coeffs.length > N) {
            for (int k = N; k < c.coeffs.length; k++) {
                int[] iArr = c.coeffs;
                int i = k - N;
                iArr[i] = iArr[i] + c.coeffs[k];
            }
            c.coeffs = Arrays.copyOf(c.coeffs, N);
        }
        return c;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    public BigIntPolynomial mult(BigIntPolynomial poly2) {
        return new BigIntPolynomial(this).mult(poly2);
    }

    private IntegerPolynomial multRecursive(IntegerPolynomial poly2) {
        IntegerPolynomial c;
        int[] a = this.coeffs;
        int[] b = poly2.coeffs;
        int n = poly2.coeffs.length;
        if (n <= 32) {
            int cn2 = (n * 2) - 1;
            c = new IntegerPolynomial(new int[cn2]);
            for (int k = 0; k < cn2; k++) {
                for (int i = Math.max(0, (k - n) + 1); i <= Math.min(k, n - 1); i++) {
                    int[] iArr = c.coeffs;
                    iArr[k] = iArr[k] + (b[i] * a[k - i]);
                }
            }
        } else {
            int n1 = n / 2;
            IntegerPolynomial a1 = new IntegerPolynomial(Arrays.copyOf(a, n1));
            IntegerPolynomial a2 = new IntegerPolynomial(Arrays.copyOfRange(a, n1, n));
            IntegerPolynomial b1 = new IntegerPolynomial(Arrays.copyOf(b, n1));
            IntegerPolynomial b2 = new IntegerPolynomial(Arrays.copyOfRange(b, n1, n));
            IntegerPolynomial A = (IntegerPolynomial) a1.clone();
            A.add(a2);
            IntegerPolynomial B = (IntegerPolynomial) b1.clone();
            B.add(b2);
            IntegerPolynomial c1 = a1.multRecursive(b1);
            IntegerPolynomial c2 = a2.multRecursive(b2);
            IntegerPolynomial c3 = A.multRecursive(B);
            c3.sub(c1);
            c3.sub(c2);
            c = new IntegerPolynomial((n * 2) - 1);
            for (int i2 = 0; i2 < c1.coeffs.length; i2++) {
                c.coeffs[i2] = c1.coeffs[i2];
            }
            for (int i3 = 0; i3 < c3.coeffs.length; i3++) {
                int[] iArr2 = c.coeffs;
                int i4 = n1 + i3;
                iArr2[i4] = iArr2[i4] + c3.coeffs[i3];
            }
            for (int i5 = 0; i5 < c2.coeffs.length; i5++) {
                int[] iArr3 = c.coeffs;
                int i6 = (n1 * 2) + i5;
                iArr3[i6] = iArr3[i6] + c2.coeffs[i5];
            }
        }
        return c;
    }

    public IntegerPolynomial invertFq(int q) {
        int N = this.coeffs.length;
        int k = 0;
        IntegerPolynomial b = new IntegerPolynomial(N + 1);
        b.coeffs[0] = 1;
        IntegerPolynomial c = new IntegerPolynomial(N + 1);
        IntegerPolynomial f = new IntegerPolynomial(N + 1);
        f.coeffs = Arrays.copyOf(this.coeffs, N + 1);
        f.modPositive(2);
        IntegerPolynomial g = new IntegerPolynomial(N + 1);
        g.coeffs[0] = 1;
        g.coeffs[N] = 1;
        while (true) {
            if (f.coeffs[0] == 0) {
                for (int i = 1; i <= N; i++) {
                    f.coeffs[i - 1] = f.coeffs[i];
                    c.coeffs[(N + 1) - i] = c.coeffs[N - i];
                }
                f.coeffs[N] = 0;
                c.coeffs[0] = 0;
                k++;
                if (f.equalsZero()) {
                    return null;
                }
            } else if (!f.equalsOne()) {
                if (f.degree() < g.degree()) {
                    f = g;
                    g = f;
                    b = c;
                    c = b;
                }
                f.add(g, 2);
                b.add(c, 2);
            } else if (b.coeffs[N] != 0) {
                return null;
            } else {
                IntegerPolynomial Fq = new IntegerPolynomial(N);
                int k2 = k % N;
                for (int i2 = N - 1; i2 >= 0; i2--) {
                    int j = i2 - k2;
                    if (j < 0) {
                        j += N;
                    }
                    Fq.coeffs[j] = b.coeffs[i2];
                }
                return mod2ToModq(Fq, q);
            }
        }
    }

    private IntegerPolynomial mod2ToModq(IntegerPolynomial Fq, int q) {
        if (!Util.is64BitJVM() || q != 2048) {
            int v = 2;
            IntegerPolynomial Fq2 = Fq;
            while (v < q) {
                v *= 2;
                IntegerPolynomial temp = new IntegerPolynomial(Arrays.copyOf(Fq2.coeffs, Fq2.coeffs.length));
                temp.mult2(v);
                temp.sub(mult(Fq2, v).mult(Fq2, v), v);
                Fq2 = temp;
            }
            return Fq2;
        }
        LongPolynomial2 thisLong = new LongPolynomial2(this);
        LongPolynomial2 FqLong = new LongPolynomial2(Fq);
        int v2 = 2;
        while (v2 < q) {
            v2 *= 2;
            LongPolynomial2 temp2 = (LongPolynomial2) FqLong.clone();
            temp2.mult2And(v2 - 1);
            temp2.subAnd(thisLong.mult(FqLong).mult(FqLong), v2 - 1);
            FqLong = temp2;
        }
        return FqLong.toIntegerPolynomial();
    }

    public IntegerPolynomial invertF3() {
        int N = this.coeffs.length;
        int k = 0;
        IntegerPolynomial b = new IntegerPolynomial(N + 1);
        b.coeffs[0] = 1;
        IntegerPolynomial c = new IntegerPolynomial(N + 1);
        IntegerPolynomial f = new IntegerPolynomial(N + 1);
        f.coeffs = Arrays.copyOf(this.coeffs, N + 1);
        f.modPositive(3);
        IntegerPolynomial g = new IntegerPolynomial(N + 1);
        g.coeffs[0] = -1;
        g.coeffs[N] = 1;
        while (true) {
            if (f.coeffs[0] == 0) {
                for (int i = 1; i <= N; i++) {
                    f.coeffs[i - 1] = f.coeffs[i];
                    c.coeffs[(N + 1) - i] = c.coeffs[N - i];
                }
                f.coeffs[N] = 0;
                c.coeffs[0] = 0;
                k++;
                if (f.equalsZero()) {
                    return null;
                }
            } else if (!f.equalsAbsOne()) {
                if (f.degree() < g.degree()) {
                    f = g;
                    g = f;
                    b = c;
                    c = b;
                }
                if (f.coeffs[0] == g.coeffs[0]) {
                    f.sub(g, 3);
                    b.sub(c, 3);
                } else {
                    f.add(g, 3);
                    b.add(c, 3);
                }
            } else if (b.coeffs[N] != 0) {
                return null;
            } else {
                IntegerPolynomial Fp = new IntegerPolynomial(N);
                int k2 = k % N;
                for (int i2 = N - 1; i2 >= 0; i2--) {
                    int j = i2 - k2;
                    if (j < 0) {
                        j += N;
                    }
                    Fp.coeffs[j] = f.coeffs[0] * b.coeffs[i2];
                }
                Fp.ensurePositive(3);
                return Fp;
            }
        }
    }

    public Resultant resultant() {
        int N = this.coeffs.length;
        LinkedList<ModularResultant> modResultants = new LinkedList<>();
        BigInteger pProd = Constants.BIGINT_ONE;
        BigInteger res = Constants.BIGINT_ONE;
        int numEqual = 1;
        PrimeGenerator primes = new PrimeGenerator();
        while (true) {
            BigInteger prime = primes.nextPrime();
            ModularResultant crr = resultant(prime.intValue());
            modResultants.add(crr);
            BigInteger temp = pProd.multiply(prime);
            BigIntEuclidean er = BigIntEuclidean.calculate(prime, pProd);
            res = res.multiply(er.x.multiply(prime)).add(crr.res.multiply(er.y.multiply(pProd))).mod(temp);
            pProd = temp;
            BigInteger pProd2 = pProd.divide(BigInteger.valueOf(2));
            BigInteger pProd2n = pProd2.negate();
            if (res.compareTo(pProd2) > 0) {
                res = res.subtract(pProd);
            } else if (res.compareTo(pProd2n) < 0) {
                res = res.add(pProd);
            }
            if (res.equals(res)) {
                numEqual++;
                if (numEqual >= 3) {
                    break;
                }
            } else {
                numEqual = 1;
            }
        }
        while (modResultants.size() > 1) {
            modResultants.addLast(ModularResultant.combineRho(modResultants.removeFirst(), modResultants.removeFirst()));
        }
        BigIntPolynomial rhoP = modResultants.getFirst().rho;
        BigInteger pProd22 = pProd.divide(BigInteger.valueOf(2));
        BigInteger pProd2n2 = pProd22.negate();
        if (res.compareTo(pProd22) > 0) {
            res = res.subtract(pProd);
        }
        if (res.compareTo(pProd2n2) < 0) {
            res = res.add(pProd);
        }
        for (int i = 0; i < N; i++) {
            BigInteger c = rhoP.coeffs[i];
            if (c.compareTo(pProd22) > 0) {
                rhoP.coeffs[i] = c.subtract(pProd);
            }
            if (c.compareTo(pProd2n2) < 0) {
                rhoP.coeffs[i] = c.add(pProd);
            }
        }
        return new Resultant(rhoP, res);
    }

    public Resultant resultantMultiThread() {
        int N = this.coeffs.length;
        BigInteger max2 = squareSum().pow((N + 1) / 2).multiply(BigInteger.valueOf(2).pow((degree() + 1) / 2)).multiply(BigInteger.valueOf(2));
        BigInteger prime = BigInteger.valueOf(10000);
        BigInteger pProd = Constants.BIGINT_ONE;
        LinkedBlockingQueue<Future<ModularResultant>> resultantTasks = new LinkedBlockingQueue<>();
        Iterator<BigInteger> primes = BIGINT_PRIMES.iterator();
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        while (pProd.compareTo(max2) < 0) {
            if (primes.hasNext()) {
                prime = primes.next();
            } else {
                prime = prime.nextProbablePrime();
            }
            resultantTasks.add(executor.submit(new ModResultantTask(prime.intValue())));
            pProd = pProd.multiply(prime);
        }
        ModularResultant overallResultant = null;
        while (true) {
            if (resultantTasks.isEmpty()) {
                break;
            }
            try {
                Future<ModularResultant> modRes1 = resultantTasks.take();
                Future<ModularResultant> modRes2 = resultantTasks.poll();
                if (modRes2 == null) {
                    overallResultant = modRes1.get();
                    break;
                }
                resultantTasks.add(executor.submit(new CombineTask(modRes1.get(), modRes2.get())));
            } catch (Exception e) {
                throw new IllegalStateException(e.toString());
            }
        }
        executor.shutdown();
        BigInteger res = overallResultant.res;
        BigIntPolynomial rhoP = overallResultant.rho;
        BigInteger pProd2 = pProd.divide(BigInteger.valueOf(2));
        BigInteger pProd2n = pProd2.negate();
        if (res.compareTo(pProd2) > 0) {
            res = res.subtract(pProd);
        }
        if (res.compareTo(pProd2n) < 0) {
            res = res.add(pProd);
        }
        for (int i = 0; i < N; i++) {
            BigInteger c = rhoP.coeffs[i];
            if (c.compareTo(pProd2) > 0) {
                rhoP.coeffs[i] = c.subtract(pProd);
            }
            if (c.compareTo(pProd2n) < 0) {
                rhoP.coeffs[i] = c.add(pProd);
            }
        }
        return new Resultant(rhoP, res);
    }

    public ModularResultant resultant(int p) {
        int[] fcoeffs = Arrays.copyOf(this.coeffs, this.coeffs.length + 1);
        IntegerPolynomial f = new IntegerPolynomial(fcoeffs);
        int N = fcoeffs.length;
        IntegerPolynomial a = new IntegerPolynomial(N);
        a.coeffs[0] = -1;
        a.coeffs[N - 1] = 1;
        IntegerPolynomial b = new IntegerPolynomial(f.coeffs);
        IntegerPolynomial v1 = new IntegerPolynomial(N);
        IntegerPolynomial v2 = new IntegerPolynomial(N);
        v2.coeffs[0] = 1;
        int da = N - 1;
        int db = b.degree();
        int ta = da;
        int r = 1;
        while (db > 0) {
            int c = (a.coeffs[da] * Util.invert(b.coeffs[db], p)) % p;
            a.multShiftSub(b, c, da - db, p);
            v1.multShiftSub(v2, c, da - db, p);
            da = a.degree();
            if (da < db) {
                r = (r * Util.pow(b.coeffs[db], ta - da, p)) % p;
                if (ta % 2 == 1 && db % 2 == 1) {
                    r = (-r) % p;
                }
                a = b;
                b = a;
                da = db;
                v1 = v2;
                v2 = v1;
                ta = db;
                db = da;
            }
        }
        int r2 = (r * Util.pow(b.coeffs[0], da, p)) % p;
        v2.mult(Util.invert(b.coeffs[0], p));
        v2.mod(p);
        v2.mult(r2);
        v2.mod(p);
        v2.coeffs = Arrays.copyOf(v2.coeffs, v2.coeffs.length - 1);
        return new ModularResultant(new BigIntPolynomial(v2), BigInteger.valueOf((long) r2), BigInteger.valueOf((long) p));
    }

    private void multShiftSub(IntegerPolynomial b, int c, int k, int p) {
        int N = this.coeffs.length;
        for (int i = k; i < N; i++) {
            this.coeffs[i] = (this.coeffs[i] - (b.coeffs[i - k] * c)) % p;
        }
    }

    private BigInteger squareSum() {
        BigInteger sum = Constants.BIGINT_ZERO;
        for (int i = 0; i < this.coeffs.length; i++) {
            sum = sum.add(BigInteger.valueOf((long) (this.coeffs[i] * this.coeffs[i])));
        }
        return sum;
    }

    /* access modifiers changed from: package-private */
    public int degree() {
        int degree = this.coeffs.length - 1;
        while (degree > 0 && this.coeffs[degree] == 0) {
            degree--;
        }
        return degree;
    }

    public void add(IntegerPolynomial b, int modulus) {
        add(b);
        mod(modulus);
    }

    public void add(IntegerPolynomial b) {
        if (b.coeffs.length > this.coeffs.length) {
            this.coeffs = Arrays.copyOf(this.coeffs, b.coeffs.length);
        }
        for (int i = 0; i < b.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = iArr[i] + b.coeffs[i];
        }
    }

    public void sub(IntegerPolynomial b, int modulus) {
        sub(b);
        mod(modulus);
    }

    public void sub(IntegerPolynomial b) {
        if (b.coeffs.length > this.coeffs.length) {
            this.coeffs = Arrays.copyOf(this.coeffs, b.coeffs.length);
        }
        for (int i = 0; i < b.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = iArr[i] - b.coeffs[i];
        }
    }

    /* access modifiers changed from: package-private */
    public void sub(int b) {
        for (int i = 0; i < this.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = iArr[i] - b;
        }
    }

    public void mult(int factor) {
        for (int i = 0; i < this.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = iArr[i] * factor;
        }
    }

    private void mult2(int modulus) {
        for (int i = 0; i < this.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = iArr[i] * 2;
            int[] iArr2 = this.coeffs;
            iArr2[i] = iArr2[i] % modulus;
        }
    }

    public void mult3(int modulus) {
        for (int i = 0; i < this.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = iArr[i] * 3;
            int[] iArr2 = this.coeffs;
            iArr2[i] = iArr2[i] % modulus;
        }
    }

    public void div(int k) {
        int k2 = (k + 1) / 2;
        for (int i = 0; i < this.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = (this.coeffs[i] > 0 ? k2 : -k2) + iArr[i];
            int[] iArr2 = this.coeffs;
            iArr2[i] = iArr2[i] / k;
        }
    }

    public void mod3() {
        for (int i = 0; i < this.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = iArr[i] % 3;
            if (this.coeffs[i] > 1) {
                int[] iArr2 = this.coeffs;
                iArr2[i] = iArr2[i] - 3;
            }
            if (this.coeffs[i] < -1) {
                int[] iArr3 = this.coeffs;
                iArr3[i] = iArr3[i] + 3;
            }
        }
    }

    public void modPositive(int modulus) {
        mod(modulus);
        ensurePositive(modulus);
    }

    /* access modifiers changed from: package-private */
    public void modCenter(int modulus) {
        mod(modulus);
        for (int j = 0; j < this.coeffs.length; j++) {
            while (this.coeffs[j] < modulus / 2) {
                int[] iArr = this.coeffs;
                iArr[j] = iArr[j] + modulus;
            }
            while (this.coeffs[j] >= modulus / 2) {
                int[] iArr2 = this.coeffs;
                iArr2[j] = iArr2[j] - modulus;
            }
        }
    }

    public void mod(int modulus) {
        for (int i = 0; i < this.coeffs.length; i++) {
            int[] iArr = this.coeffs;
            iArr[i] = iArr[i] % modulus;
        }
    }

    public void ensurePositive(int modulus) {
        for (int i = 0; i < this.coeffs.length; i++) {
            while (this.coeffs[i] < 0) {
                int[] iArr = this.coeffs;
                iArr[i] = iArr[i] + modulus;
            }
        }
    }

    public long centeredNormSq(int q) {
        int N = this.coeffs.length;
        IntegerPolynomial p = (IntegerPolynomial) clone();
        p.shiftGap(q);
        long sum = 0;
        long sqSum = 0;
        for (int i = 0; i != p.coeffs.length; i++) {
            int c = p.coeffs[i];
            sum += (long) c;
            sqSum += (long) (c * c);
        }
        return sqSum - ((sum * sum) / ((long) N));
    }

    /* access modifiers changed from: package-private */
    public void shiftGap(int q) {
        int shift;
        modCenter(q);
        int[] sorted = Arrays.clone(this.coeffs);
        sort(sorted);
        int maxrange = 0;
        int maxrangeStart = 0;
        for (int i = 0; i < sorted.length - 1; i++) {
            int range = sorted[i + 1] - sorted[i];
            if (range > maxrange) {
                maxrange = range;
                maxrangeStart = sorted[i];
            }
        }
        int pmin = sorted[0];
        int pmax = sorted[sorted.length - 1];
        if ((q - pmax) + pmin > maxrange) {
            shift = (pmax + pmin) / 2;
        } else {
            shift = (maxrange / 2) + maxrangeStart + (q / 2);
        }
        sub(shift);
    }

    private void sort(int[] ints) {
        boolean swap = true;
        while (swap) {
            swap = false;
            for (int i = 0; i != ints.length - 1; i++) {
                if (ints[i] > ints[i + 1]) {
                    int tmp = ints[i];
                    ints[i] = ints[i + 1];
                    ints[i + 1] = tmp;
                    swap = true;
                }
            }
        }
    }

    public void center0(int q) {
        for (int i = 0; i < this.coeffs.length; i++) {
            while (this.coeffs[i] < (-q) / 2) {
                int[] iArr = this.coeffs;
                iArr[i] = iArr[i] + q;
            }
            while (this.coeffs[i] > q / 2) {
                int[] iArr2 = this.coeffs;
                iArr2[i] = iArr2[i] - q;
            }
        }
    }

    public int sumCoeffs() {
        int sum = 0;
        for (int i = 0; i < this.coeffs.length; i++) {
            sum += this.coeffs[i];
        }
        return sum;
    }

    private boolean equalsZero() {
        for (int i = 0; i < this.coeffs.length; i++) {
            if (this.coeffs[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public boolean equalsOne() {
        boolean z = true;
        for (int i = 1; i < this.coeffs.length; i++) {
            if (this.coeffs[i] != 0) {
                return false;
            }
        }
        if (this.coeffs[0] != 1) {
            z = false;
        }
        return z;
    }

    private boolean equalsAbsOne() {
        boolean z = true;
        for (int i = 1; i < this.coeffs.length; i++) {
            if (this.coeffs[i] != 0) {
                return false;
            }
        }
        if (Math.abs(this.coeffs[0]) != 1) {
            z = false;
        }
        return z;
    }

    public int count(int value) {
        int count = 0;
        for (int i = 0; i != this.coeffs.length; i++) {
            if (this.coeffs[i] == value) {
                count++;
            }
        }
        return count;
    }

    public void rotate1() {
        int clast = this.coeffs[this.coeffs.length - 1];
        for (int i = this.coeffs.length - 1; i > 0; i--) {
            this.coeffs[i] = this.coeffs[i - 1];
        }
        this.coeffs[0] = clast;
    }

    public void clear() {
        for (int i = 0; i < this.coeffs.length; i++) {
            this.coeffs[i] = 0;
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    public IntegerPolynomial toIntegerPolynomial() {
        return (IntegerPolynomial) clone();
    }

    public Object clone() {
        return new IntegerPolynomial((int[]) this.coeffs.clone());
    }

    public boolean equals(Object obj) {
        if (obj instanceof IntegerPolynomial) {
            return Arrays.areEqual(this.coeffs, ((IntegerPolynomial) obj).coeffs);
        }
        return false;
    }

    private class ModResultantTask implements Callable<ModularResultant> {
        private int modulus;

        private ModResultantTask(int modulus2) {
            this.modulus = modulus2;
        }

        @Override // java.util.concurrent.Callable
        public ModularResultant call() {
            return IntegerPolynomial.this.resultant(this.modulus);
        }
    }

    private class CombineTask implements Callable<ModularResultant> {
        private ModularResultant modRes1;
        private ModularResultant modRes2;

        private CombineTask(ModularResultant modRes12, ModularResultant modRes22) {
            this.modRes1 = modRes12;
            this.modRes2 = modRes22;
        }

        @Override // java.util.concurrent.Callable
        public ModularResultant call() {
            return ModularResultant.combineRho(this.modRes1, this.modRes2);
        }
    }

    private class PrimeGenerator {
        private int index;
        private BigInteger prime;

        private PrimeGenerator() {
            this.index = 0;
        }

        public BigInteger nextPrime() {
            if (this.index < IntegerPolynomial.BIGINT_PRIMES.size()) {
                List list = IntegerPolynomial.BIGINT_PRIMES;
                int i = this.index;
                this.index = i + 1;
                this.prime = (BigInteger) list.get(i);
            } else {
                this.prime = this.prime.nextProbablePrime();
            }
            return this.prime;
        }
    }
}
