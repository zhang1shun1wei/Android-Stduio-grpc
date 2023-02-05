package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.util.HashSet;
import java.util.Set;

public class XMSSUtil {
    public static int log2(int n) {
        int log = 0;
        while (true) {
            n >>= 1;
            if (n == 0) {
                return log;
            }
            log++;
        }
    }

    public static byte[] toBytesBigEndian(long value, int sizeInByte) {
        byte[] out = new byte[sizeInByte];
        for (int i = sizeInByte - 1; i >= 0; i--) {
            out[i] = (byte) ((int) value);
            value >>>= 8;
        }
        return out;
    }

    public static void longToBigEndian(long value, byte[] in, int offset) {
        if (in == null) {
            throw new NullPointerException("in == null");
        } else if (in.length - offset < 8) {
            throw new IllegalArgumentException("not enough space in array");
        } else {
            in[offset] = (byte) ((int) ((value >> 56) & 255));
            in[offset + 1] = (byte) ((int) ((value >> 48) & 255));
            in[offset + 2] = (byte) ((int) ((value >> 40) & 255));
            in[offset + 3] = (byte) ((int) ((value >> 32) & 255));
            in[offset + 4] = (byte) ((int) ((value >> 24) & 255));
            in[offset + 5] = (byte) ((int) ((value >> 16) & 255));
            in[offset + 6] = (byte) ((int) ((value >> 8) & 255));
            in[offset + 7] = (byte) ((int) (value & 255));
        }
    }

    public static long bytesToXBigEndian(byte[] in, int offset, int size) {
        if (in == null) {
            throw new NullPointerException("in == null");
        }
        long res = 0;
        for (int i = offset; i < offset + size; i++) {
            res = (res << 8) | ((long) (in[i] & 255));
        }
        return res;
    }

    public static byte[] cloneArray(byte[] in) {
        if (in == null) {
            throw new NullPointerException("in == null");
        }
        byte[] out = new byte[in.length];
        System.arraycopy(in, 0, out, 0, in.length);
        return out;
    }

    public static byte[][] cloneArray(byte[][] in) {
        if (hasNullPointer(in)) {
            throw new NullPointerException("in has null pointers");
        }
        byte[][] out = new byte[in.length][];
        for (int i = 0; i < in.length; i++) {
            out[i] = new byte[in[i].length];
            System.arraycopy(in[i], 0, out[i], 0, in[i].length);
        }
        return out;
    }

    public static boolean areEqual(byte[][] a, byte[][] b) {
        if (hasNullPointer(a) || hasNullPointer(b)) {
            throw new NullPointerException("a or b == null");
        }
        for (int i = 0; i < a.length; i++) {
            if (!Arrays.areEqual(a[i], b[i])) {
                return false;
            }
        }
        return true;
    }

    public static void dumpByteArray(byte[][] x) {
        if (hasNullPointer(x)) {
            throw new NullPointerException("x has null pointers");
        }
        for (byte[] bArr : x) {
            System.out.println(Hex.toHexString(bArr));
        }
    }

    public static boolean hasNullPointer(byte[][] in) {
        if (in == null) {
            return true;
        }
        for (byte[] bArr : in) {
            if (bArr == null) {
                return true;
            }
        }
        return false;
    }

    public static void copyBytesAtOffset(byte[] dst, byte[] src, int offset) {
        if (dst == null) {
            throw new NullPointerException("dst == null");
        } else if (src == null) {
            throw new NullPointerException("src == null");
        } else if (offset < 0) {
            throw new IllegalArgumentException("offset hast to be >= 0");
        } else if (src.length + offset > dst.length) {
            throw new IllegalArgumentException("src length + offset must not be greater than size of destination");
        } else {
            for (int i = 0; i < src.length; i++) {
                dst[offset + i] = src[i];
            }
        }
    }

    public static byte[] extractBytesAtOffset(byte[] src, int offset, int length) {
        if (src == null) {
            throw new NullPointerException("src == null");
        } else if (offset < 0) {
            throw new IllegalArgumentException("offset hast to be >= 0");
        } else if (length < 0) {
            throw new IllegalArgumentException("length hast to be >= 0");
        } else if (offset + length > src.length) {
            throw new IllegalArgumentException("offset + length must not be greater then size of source array");
        } else {
            byte[] out = new byte[length];
            for (int i = 0; i < out.length; i++) {
                out[i] = src[offset + i];
            }
            return out;
        }
    }

    public static boolean isIndexValid(int height, long index) {
        if (index >= 0) {
            return index < (1 << height);
        }
        throw new IllegalStateException("index must not be negative");
    }

    public static int getDigestSize(Digest digest) {
        if (digest == null) {
            throw new NullPointerException("digest == null");
        }
        String algorithmName = digest.getAlgorithmName();
        if (algorithmName.equals("SHAKE128")) {
            return 32;
        }
        if (algorithmName.equals("SHAKE256")) {
            return 64;
        }
        return digest.getDigestSize();
    }

    public static long getTreeIndex(long index, int xmssTreeHeight) {
        return index >> xmssTreeHeight;
    }

    public static int getLeafIndex(long index, int xmssTreeHeight) {
        return (int) (((1 << xmssTreeHeight) - 1) & index);
    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(out);
        oos.writeObject(obj);
        oos.flush();
        return out.toByteArray();
    }

    public static Object deserialize(byte[] data, Class clazz) throws IOException, ClassNotFoundException {
        ObjectInputStream is = new CheckingStream(clazz, new ByteArrayInputStream(data));
        Object obj = is.readObject();
        if (is.available() != 0) {
            throw new IOException("unexpected data found at end of ObjectInputStream");
        } else if (clazz.isInstance(obj)) {
            return obj;
        } else {
            throw new IOException("unexpected class found in ObjectInputStream");
        }
    }

    public static int calculateTau(int index, int height) {
        for (int i = 0; i < height; i++) {
            if (((index >> i) & 1) == 0) {
                return i;
            }
        }
        return 0;
    }

    public static boolean isNewBDSInitNeeded(long globalIndex, int xmssHeight, int layer) {
        boolean z = true;
        if (globalIndex == 0) {
            return false;
        }
        if (globalIndex % ((long) Math.pow((double) (1 << xmssHeight), (double) (layer + 1))) != 0) {
            z = false;
        }
        return z;
    }

    public static boolean isNewAuthenticationPathNeeded(long globalIndex, int xmssHeight, int layer) {
        boolean z = true;
        if (globalIndex == 0) {
            return false;
        }
        if ((1 + globalIndex) % ((long) Math.pow((double) (1 << xmssHeight), (double) layer)) != 0) {
            z = false;
        }
        return z;
    }

    /* access modifiers changed from: private */
    public static class CheckingStream extends ObjectInputStream {
        private static final Set components = new HashSet();
        private boolean found = false;
        private final Class mainClass;

        static {
            components.add("java.util.TreeMap");
            components.add("java.lang.Integer");
            components.add("java.lang.Number");
            components.add("com.mi.car.jsse.easysec.pqc.crypto.xmss.BDS");
            components.add("java.util.ArrayList");
            components.add("com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSNode");
            components.add("[B");
            components.add("java.util.LinkedList");
            components.add("java.util.Stack");
            components.add("java.util.Vector");
            components.add("[Ljava.lang.Object;");
            components.add("com.mi.car.jsse.easysec.pqc.crypto.xmss.BDSTreeHash");
        }

        CheckingStream(Class mainClass2, InputStream in) throws IOException {
            super(in);
            this.mainClass = mainClass2;
        }

        /* access modifiers changed from: protected */
        @Override // java.io.ObjectInputStream
        public Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            if (!this.found) {
                if (!desc.getName().equals(this.mainClass.getName())) {
                    throw new InvalidClassException("unexpected class: ", desc.getName());
                }
                this.found = true;
            } else if (!components.contains(desc.getName())) {
                throw new InvalidClassException("unexpected class: ", desc.getName());
            }
            return super.resolveClass(desc);
        }
    }
}
