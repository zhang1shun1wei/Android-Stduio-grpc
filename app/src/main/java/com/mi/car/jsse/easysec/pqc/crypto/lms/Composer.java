package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.digests.Blake2xsDigest;
import com.mi.car.jsse.easysec.util.Encodable;
import java.io.ByteArrayOutputStream;

public class Composer {
    private final ByteArrayOutputStream bos = new ByteArrayOutputStream();

    private Composer() {
    }

    public static Composer compose() {
        return new Composer();
    }

    public Composer u64str(long n) {
        u32str((int) (n >>> 32));
        u32str((int) n);
        return this;
    }

    public Composer u32str(int n) {
        this.bos.write((byte) (n >>> 24));
        this.bos.write((byte) (n >>> 16));
        this.bos.write((byte) (n >>> 8));
        this.bos.write((byte) n);
        return this;
    }

    public Composer u16str(int n) {
        int n2 = n & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH;
        this.bos.write((byte) (n2 >>> 8));
        this.bos.write((byte) n2);
        return this;
    }

    public Composer bytes(Encodable[] encodable) {
        try {
            for (Encodable e : encodable) {
                this.bos.write(e.getEncoded());
            }
            return this;
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public Composer bytes(Encodable encodable) {
        try {
            this.bos.write(encodable.getEncoded());
            return this;
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public Composer pad(int v, int len) {
        while (len >= 0) {
            try {
                this.bos.write(v);
                len--;
            } catch (Exception ex) {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }
        return this;
    }

    public Composer bytes(byte[][] arrays) {
        try {
            for (byte[] array : arrays) {
                this.bos.write(array);
            }
            return this;
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public Composer bytes(byte[][] arrays, int start, int end) {
        for (int j = start; j != end; j++) {
            try {
                this.bos.write(arrays[j]);
            } catch (Exception ex) {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }
        return this;
    }

    public Composer bytes(byte[] array) {
        try {
            this.bos.write(array);
            return this;
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public Composer bytes(byte[] array, int start, int len) {
        try {
            this.bos.write(array, start, len);
            return this;
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public byte[] build() {
        return this.bos.toByteArray();
    }

    public Composer padUntil(int v, int requiredLen) {
        while (this.bos.size() < requiredLen) {
            this.bos.write(v);
        }
        return this;
    }

    public Composer bool(boolean v) {
        this.bos.write(v ? 1 : 0);
        return this;
    }
}
