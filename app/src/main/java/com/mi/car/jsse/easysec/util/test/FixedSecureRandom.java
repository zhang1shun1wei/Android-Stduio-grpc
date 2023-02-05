package com.mi.car.jsse.easysec.util.test;

import com.mi.car.jsse.easysec.util.Pack;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.SecureRandom;

public class FixedSecureRandom extends SecureRandom {
    private static java.math.BigInteger ANDROID = new java.math.BigInteger("1111111105060708ffffffff01020304", 16);
    private static java.math.BigInteger CLASSPATH = new java.math.BigInteger("3020104ffffffff05060708111111", 16);
    private static java.math.BigInteger REGULAR = new java.math.BigInteger("01020304ffffffff0506070811111111", 16);
    private static final boolean isAndroidStyle;
    private static final boolean isClasspathStyle;
    private static final boolean isRegularStyle;
    private byte[] _data;
    private int _index;

    static {
        java.math.BigInteger check1 = new java.math.BigInteger(128, new RandomChecker());
        java.math.BigInteger check2 = new java.math.BigInteger(120, new RandomChecker());
        isAndroidStyle = check1.equals(ANDROID);
        isRegularStyle = check1.equals(REGULAR);
        isClasspathStyle = check2.equals(CLASSPATH);
    }

    public static class Source {
        byte[] data;

        Source(byte[] data2) {
            this.data = data2;
        }
    }

    public static class Data extends Source {
        public Data(byte[] data) {
            super(data);
        }
    }

    public static class BigInteger extends Source {
        public BigInteger(byte[] data) {
            super(data);
        }

        public BigInteger(int bitLength, byte[] data) {
            super(FixedSecureRandom.expandToBitLength(bitLength, data));
        }

        public BigInteger(String hexData) {
            this(Hex.decode(hexData));
        }

        public BigInteger(int bitLength, String hexData) {
            super(FixedSecureRandom.expandToBitLength(bitLength, Hex.decode(hexData)));
        }
    }

    public FixedSecureRandom(byte[] value) {
        this(new Source[]{new Data(value)});
    }

    public FixedSecureRandom(byte[][] values) {
        this(buildDataArray(values));
    }

    private static Data[] buildDataArray(byte[][] values) {
        Data[] res = new Data[values.length];
        for (int i = 0; i != values.length; i++) {
            res[i] = new Data(values[i]);
        }
        return res;
    }

    public FixedSecureRandom(Source[] sources) {
        super(null, new DummyProvider());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        if (isRegularStyle) {
            if (isClasspathStyle) {
                for (int i = 0; i != sources.length; i++) {
                    try {
                        if (sources[i] instanceof BigInteger) {
                            byte[] data = sources[i].data;
                            int len = data.length - (data.length % 4);
                            for (int w = (data.length - len) - 1; w >= 0; w--) {
                                bOut.write(data[w]);
                            }
                            for (int w2 = data.length - len; w2 < data.length; w2 += 4) {
                                bOut.write(data, w2, 4);
                            }
                        } else {
                            bOut.write(sources[i].data);
                        }
                    } catch (IOException e) {
                        throw new IllegalArgumentException("can't save value source.");
                    }
                }
            } else {
                for (int i2 = 0; i2 != sources.length; i2++) {
                    try {
                        bOut.write(sources[i2].data);
                    } catch (IOException e2) {
                        throw new IllegalArgumentException("can't save value source.");
                    }
                }
            }
        } else if (isAndroidStyle) {
            for (int i3 = 0; i3 != sources.length; i3++) {
                try {
                    if (sources[i3] instanceof BigInteger) {
                        byte[] data2 = sources[i3].data;
                        int len2 = data2.length - (data2.length % 4);
                        for (int w3 = 0; w3 < len2; w3 += 4) {
                            bOut.write(data2, data2.length - (w3 + 4), 4);
                        }
                        if (data2.length - len2 != 0) {
                            for (int w4 = 0; w4 != 4 - (data2.length - len2); w4++) {
                                bOut.write(0);
                            }
                        }
                        for (int w5 = 0; w5 != data2.length - len2; w5++) {
                            bOut.write(data2[len2 + w5]);
                        }
                    } else {
                        bOut.write(sources[i3].data);
                    }
                } catch (IOException e3) {
                    throw new IllegalArgumentException("can't save value source.");
                }
            }
        } else {
            throw new IllegalStateException("Unrecognized BigInteger implementation");
        }
        this._data = bOut.toByteArray();
    }

    public void nextBytes(byte[] bytes) {
        System.arraycopy(this._data, this._index, bytes, 0, bytes.length);
        this._index += bytes.length;
    }

    public byte[] generateSeed(int numBytes) {
        byte[] bytes = new byte[numBytes];
        nextBytes(bytes);
        return bytes;
    }

    public int nextInt() {
        return 0 | (nextValue() << 24) | (nextValue() << 16) | (nextValue() << 8) | nextValue();
    }

    public long nextLong() {
        return 0 | (((long) nextValue()) << 56) | (((long) nextValue()) << 48) | (((long) nextValue()) << 40) | (((long) nextValue()) << 32) | (((long) nextValue()) << 24) | (((long) nextValue()) << 16) | (((long) nextValue()) << 8) | ((long) nextValue());
    }

    public boolean isExhausted() {
        return this._index == this._data.length;
    }

    private int nextValue() {
        byte[] bArr = this._data;
        int i = this._index;
        this._index = i + 1;
        return bArr[i] & 255;
    }

    private static class RandomChecker extends SecureRandom {
        byte[] data = Hex.decode("01020304ffffffff0506070811111111");
        int index = 0;

        RandomChecker() {
            super(null, new DummyProvider());
        }

        public void nextBytes(byte[] bytes) {
            System.arraycopy(this.data, this.index, bytes, 0, bytes.length);
            this.index += bytes.length;
        }
    }

    /* access modifiers changed from: private */
    public static byte[] expandToBitLength(int bitLength, byte[] v) {
        if ((bitLength + 7) / 8 > v.length) {
            byte[] tmp = new byte[((bitLength + 7) / 8)];
            System.arraycopy(v, 0, tmp, tmp.length - v.length, v.length);
            if (!isAndroidStyle || bitLength % 8 == 0) {
                return tmp;
            }
            Pack.intToBigEndian(Pack.bigEndianToInt(tmp, 0) << (8 - (bitLength % 8)), tmp, 0);
            return tmp;
        }
        if (isAndroidStyle && bitLength < v.length * 8 && bitLength % 8 != 0) {
            Pack.intToBigEndian(Pack.bigEndianToInt(v, 0) << (8 - (bitLength % 8)), v, 0);
        }
        return v;
    }

    private static class DummyProvider extends Provider {
        DummyProvider() {
            super("BCFIPS_FIXED_RNG", 1.0d, "BCFIPS Fixed Secure Random Provider");
        }
    }
}
