package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.IntegerPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.ProductFormPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.SparseTernaryPolynomial;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class NTRUEncryptionPrivateKeyParameters extends NTRUEncryptionKeyParameters {
    public IntegerPolynomial fp;
    public IntegerPolynomial h;
    public Polynomial t;

    public NTRUEncryptionPrivateKeyParameters(IntegerPolynomial h2, Polynomial t2, IntegerPolynomial fp2, NTRUEncryptionParameters params) {
        super(true, params);
        this.h = h2;
        this.t = t2;
        this.fp = fp2;
    }

    public NTRUEncryptionPrivateKeyParameters(byte[] b, NTRUEncryptionParameters params) throws IOException {
        this(new ByteArrayInputStream(b), params);
    }

    public NTRUEncryptionPrivateKeyParameters(InputStream is, NTRUEncryptionParameters params) throws IOException {
        super(true, params);
        if (params.polyType == 1) {
            int N = params.N;
            int df1 = params.df1;
            int df2 = params.df2;
            int df3Ones = params.df3;
            int df3NegOnes = params.fastFp ? params.df3 : params.df3 - 1;
            this.h = IntegerPolynomial.fromBinary(is, params.N, params.q);
            this.t = ProductFormPolynomial.fromBinary(is, N, df1, df2, df3Ones, df3NegOnes);
        } else {
            this.h = IntegerPolynomial.fromBinary(is, params.N, params.q);
            IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(is, params.N);
            this.t = params.sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
        }
        init();
    }

    private void init() {
        if (this.params.fastFp) {
            this.fp = new IntegerPolynomial(this.params.N);
            this.fp.coeffs[0] = 1;
            return;
        }
        this.fp = this.t.toIntegerPolynomial().invertF3();
    }

    public byte[] getEncoded() {
        byte[] tBytes;
        byte[] hBytes = this.h.toBinary(this.params.q);
        if (this.t instanceof ProductFormPolynomial) {
            tBytes = ((ProductFormPolynomial) this.t).toBinary();
        } else {
            tBytes = this.t.toIntegerPolynomial().toBinary3Tight();
        }
        byte[] res = new byte[(hBytes.length + tBytes.length)];
        System.arraycopy(hBytes, 0, res, 0, hBytes.length);
        System.arraycopy(tBytes, 0, res, hBytes.length, tBytes.length);
        return res;
    }

    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }

    public int hashCode() {
        int i = 0;
        int hashCode = ((((this.params == null ? 0 : this.params.hashCode()) + 31) * 31) + (this.t == null ? 0 : this.t.hashCode())) * 31;
        if (this.h != null) {
            i = this.h.hashCode();
        }
        return hashCode + i;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof NTRUEncryptionPrivateKeyParameters)) {
            return false;
        }
        NTRUEncryptionPrivateKeyParameters other = (NTRUEncryptionPrivateKeyParameters) obj;
        if (this.params == null) {
            if (other.params != null) {
                return false;
            }
        } else if (!this.params.equals(other.params)) {
            return false;
        }
        if (this.t == null) {
            if (other.t != null) {
                return false;
            }
        } else if (!this.t.equals(other.t)) {
            return false;
        }
        return this.h.equals(other.h);
    }
}
