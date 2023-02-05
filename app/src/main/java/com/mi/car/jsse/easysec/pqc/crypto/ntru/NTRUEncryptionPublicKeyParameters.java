package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.IntegerPolynomial;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class NTRUEncryptionPublicKeyParameters extends NTRUEncryptionKeyParameters {
    public IntegerPolynomial h;

    public NTRUEncryptionPublicKeyParameters(IntegerPolynomial h2, NTRUEncryptionParameters params) {
        super(false, params);
        this.h = h2;
    }

    public NTRUEncryptionPublicKeyParameters(byte[] b, NTRUEncryptionParameters params) {
        super(false, params);
        this.h = IntegerPolynomial.fromBinary(b, params.N, params.q);
    }

    public NTRUEncryptionPublicKeyParameters(InputStream is, NTRUEncryptionParameters params) throws IOException {
        super(false, params);
        this.h = IntegerPolynomial.fromBinary(is, params.N, params.q);
    }

    public byte[] getEncoded() {
        return this.h.toBinary(this.params.q);
    }

    public void writeTo(OutputStream os) throws IOException {
        os.write(getEncoded());
    }

    public int hashCode() {
        int i = 0;
        int hashCode = ((this.h == null ? 0 : this.h.hashCode()) + 31) * 31;
        if (this.params != null) {
            i = this.params.hashCode();
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
        if (!(obj instanceof NTRUEncryptionPublicKeyParameters)) {
            return false;
        }
        NTRUEncryptionPublicKeyParameters other = (NTRUEncryptionPublicKeyParameters) obj;
        if (this.h == null) {
            if (other.h != null) {
                return false;
            }
        } else if (!this.h.equals(other.h)) {
            return false;
        }
        return this.params == null ? other.params == null : this.params.equals(other.params);
    }
}
