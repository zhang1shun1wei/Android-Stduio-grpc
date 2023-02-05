package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.IntegerPolynomial;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class NTRUSigningPublicKeyParameters extends AsymmetricKeyParameter {
    public IntegerPolynomial h;
    private NTRUSigningParameters params;

    public NTRUSigningPublicKeyParameters(IntegerPolynomial h2, NTRUSigningParameters params2) {
        super(false);
        this.h = h2;
        this.params = params2;
    }

    public NTRUSigningPublicKeyParameters(byte[] b, NTRUSigningParameters params2) {
        super(false);
        this.h = IntegerPolynomial.fromBinary(b, params2.N, params2.q);
        this.params = params2;
    }

    public NTRUSigningPublicKeyParameters(InputStream is, NTRUSigningParameters params2) throws IOException {
        super(false);
        this.h = IntegerPolynomial.fromBinary(is, params2.N, params2.q);
        this.params = params2;
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
        if (getClass() != obj.getClass()) {
            return false;
        }
        NTRUSigningPublicKeyParameters other = (NTRUSigningPublicKeyParameters) obj;
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
