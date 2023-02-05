package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DecimalFormat;

public class NTRUSigningKeyGenerationParameters extends KeyGenerationParameters implements Cloneable {
    public static final NTRUSigningKeyGenerationParameters APR2011_439 = new NTRUSigningKeyGenerationParameters(439, 2048, 146, 1, 1, 0.165d, 490.0d, 280.0d, false, true, 0, new SHA256Digest());
    public static final NTRUSigningKeyGenerationParameters APR2011_439_PROD = new NTRUSigningKeyGenerationParameters(439, 2048, 9, 8, 5, 1, 1, 0.165d, 490.0d, 280.0d, false, true, 0, new SHA256Digest());
    public static final NTRUSigningKeyGenerationParameters APR2011_743 = new NTRUSigningKeyGenerationParameters(743, 2048, 248, 1, 1, 0.127d, 560.0d, 360.0d, true, false, 0, new SHA512Digest());
    public static final NTRUSigningKeyGenerationParameters APR2011_743_PROD = new NTRUSigningKeyGenerationParameters(743, 2048, 11, 11, 15, 1, 1, 0.127d, 560.0d, 360.0d, true, false, 0, new SHA512Digest());
    public static final int BASIS_TYPE_STANDARD = 0;
    public static final int BASIS_TYPE_TRANSPOSE = 1;
    public static final int KEY_GEN_ALG_FLOAT = 1;
    public static final int KEY_GEN_ALG_RESULTANT = 0;
    public static final NTRUSigningKeyGenerationParameters TEST157 = new NTRUSigningKeyGenerationParameters(157, 256, 29, 1, 1, 0.38d, 200.0d, 80.0d, false, false, 0, new SHA256Digest());
    public static final NTRUSigningKeyGenerationParameters TEST157_PROD = new NTRUSigningKeyGenerationParameters(157, 256, 5, 5, 8, 1, 1, 0.38d, 200.0d, 80.0d, false, false, 0, new SHA256Digest());
    public int B;
    public int N;
    public int basisType;
    double beta;
    public double betaSq;
    int bitsF = 6;
    public int d;
    public int d1;
    public int d2;
    public int d3;
    public Digest hashAlg;
    public int keyGenAlg;
    double keyNormBound;
    public double keyNormBoundSq;
    double normBound;
    public double normBoundSq;
    public int polyType;
    public boolean primeCheck;
    public int q;
    public int signFailTolerance = 100;
    public boolean sparse;

    public NTRUSigningKeyGenerationParameters(int N2, int q2, int d4, int B2, int basisType2, double beta2, double normBound2, double keyNormBound2, boolean primeCheck2, boolean sparse2, int keyGenAlg2, Digest hashAlg2) {
        super(CryptoServicesRegistrar.getSecureRandom(), N2);
        this.N = N2;
        this.q = q2;
        this.d = d4;
        this.B = B2;
        this.basisType = basisType2;
        this.beta = beta2;
        this.normBound = normBound2;
        this.keyNormBound = keyNormBound2;
        this.primeCheck = primeCheck2;
        this.sparse = sparse2;
        this.keyGenAlg = keyGenAlg2;
        this.hashAlg = hashAlg2;
        this.polyType = 0;
        init();
    }

    public NTRUSigningKeyGenerationParameters(int N2, int q2, int d12, int d22, int d32, int B2, int basisType2, double beta2, double normBound2, double keyNormBound2, boolean primeCheck2, boolean sparse2, int keyGenAlg2, Digest hashAlg2) {
        super(CryptoServicesRegistrar.getSecureRandom(), N2);
        this.N = N2;
        this.q = q2;
        this.d1 = d12;
        this.d2 = d22;
        this.d3 = d32;
        this.B = B2;
        this.basisType = basisType2;
        this.beta = beta2;
        this.normBound = normBound2;
        this.keyNormBound = keyNormBound2;
        this.primeCheck = primeCheck2;
        this.sparse = sparse2;
        this.keyGenAlg = keyGenAlg2;
        this.hashAlg = hashAlg2;
        this.polyType = 1;
        init();
    }

    private void init() {
        this.betaSq = this.beta * this.beta;
        this.normBoundSq = this.normBound * this.normBound;
        this.keyNormBoundSq = this.keyNormBound * this.keyNormBound;
    }

    public NTRUSigningKeyGenerationParameters(InputStream is) throws IOException {
        super(CryptoServicesRegistrar.getSecureRandom(), 0);
        DataInputStream dis = new DataInputStream(is);
        this.N = dis.readInt();
        this.q = dis.readInt();
        this.d = dis.readInt();
        this.d1 = dis.readInt();
        this.d2 = dis.readInt();
        this.d3 = dis.readInt();
        this.B = dis.readInt();
        this.basisType = dis.readInt();
        this.beta = dis.readDouble();
        this.normBound = dis.readDouble();
        this.keyNormBound = dis.readDouble();
        this.signFailTolerance = dis.readInt();
        this.primeCheck = dis.readBoolean();
        this.sparse = dis.readBoolean();
        this.bitsF = dis.readInt();
        this.keyGenAlg = dis.read();
        String alg = dis.readUTF();
        if ("SHA-512".equals(alg)) {
            this.hashAlg = new SHA512Digest();
        } else if ("SHA-256".equals(alg)) {
            this.hashAlg = new SHA256Digest();
        }
        this.polyType = dis.read();
        init();
    }

    public void writeTo(OutputStream os) throws IOException {
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(this.N);
        dos.writeInt(this.q);
        dos.writeInt(this.d);
        dos.writeInt(this.d1);
        dos.writeInt(this.d2);
        dos.writeInt(this.d3);
        dos.writeInt(this.B);
        dos.writeInt(this.basisType);
        dos.writeDouble(this.beta);
        dos.writeDouble(this.normBound);
        dos.writeDouble(this.keyNormBound);
        dos.writeInt(this.signFailTolerance);
        dos.writeBoolean(this.primeCheck);
        dos.writeBoolean(this.sparse);
        dos.writeInt(this.bitsF);
        dos.write(this.keyGenAlg);
        dos.writeUTF(this.hashAlg.getAlgorithmName());
        dos.write(this.polyType);
    }

    public NTRUSigningParameters getSigningParameters() {
        return new NTRUSigningParameters(this.N, this.q, this.d, this.B, this.beta, this.normBound, this.hashAlg);
    }

    @Override // java.lang.Object
    public NTRUSigningKeyGenerationParameters clone() {
        if (this.polyType == 0) {
            return new NTRUSigningKeyGenerationParameters(this.N, this.q, this.d, this.B, this.basisType, this.beta, this.normBound, this.keyNormBound, this.primeCheck, this.sparse, this.keyGenAlg, this.hashAlg);
        }
        return new NTRUSigningKeyGenerationParameters(this.N, this.q, this.d1, this.d2, this.d3, this.B, this.basisType, this.beta, this.normBound, this.keyNormBound, this.primeCheck, this.sparse, this.keyGenAlg, this.hashAlg);
    }

    public int hashCode() {
        int hashCode;
        int i = 1231;
        long temp = Double.doubleToLongBits(this.beta);
        long temp2 = Double.doubleToLongBits(this.betaSq);
        int i2 = (((((((((((((((((((this.B + 31) * 31) + this.N) * 31) + this.basisType) * 31) + ((int) ((temp >>> 32) ^ temp))) * 31) + ((int) ((temp2 >>> 32) ^ temp2))) * 31) + this.bitsF) * 31) + this.d) * 31) + this.d1) * 31) + this.d2) * 31) + this.d3) * 31;
        if (this.hashAlg == null) {
            hashCode = 0;
        } else {
            hashCode = this.hashAlg.getAlgorithmName().hashCode();
        }
        long temp3 = Double.doubleToLongBits(this.keyNormBound);
        long temp4 = Double.doubleToLongBits(this.keyNormBoundSq);
        long temp5 = Double.doubleToLongBits(this.normBound);
        long temp6 = Double.doubleToLongBits(this.normBoundSq);
        int i3 = (((((((((((((((((((i2 + hashCode) * 31) + this.keyGenAlg) * 31) + ((int) ((temp3 >>> 32) ^ temp3))) * 31) + ((int) ((temp4 >>> 32) ^ temp4))) * 31) + ((int) ((temp5 >>> 32) ^ temp5))) * 31) + ((int) ((temp6 >>> 32) ^ temp6))) * 31) + this.polyType) * 31) + (this.primeCheck ? 1231 : 1237)) * 31) + this.q) * 31) + this.signFailTolerance) * 31;
        if (!this.sparse) {
            i = 1237;
        }
        return i3 + i;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof NTRUSigningKeyGenerationParameters)) {
            return false;
        }
        NTRUSigningKeyGenerationParameters other = (NTRUSigningKeyGenerationParameters) obj;
        if (this.B != other.B) {
            return false;
        }
        if (this.N != other.N) {
            return false;
        }
        if (this.basisType != other.basisType) {
            return false;
        }
        if (Double.doubleToLongBits(this.beta) != Double.doubleToLongBits(other.beta)) {
            return false;
        }
        if (Double.doubleToLongBits(this.betaSq) != Double.doubleToLongBits(other.betaSq)) {
            return false;
        }
        if (this.bitsF != other.bitsF) {
            return false;
        }
        if (this.d != other.d) {
            return false;
        }
        if (this.d1 != other.d1) {
            return false;
        }
        if (this.d2 != other.d2) {
            return false;
        }
        if (this.d3 != other.d3) {
            return false;
        }
        if (this.hashAlg == null) {
            if (other.hashAlg != null) {
                return false;
            }
        } else if (!this.hashAlg.getAlgorithmName().equals(other.hashAlg.getAlgorithmName())) {
            return false;
        }
        if (this.keyGenAlg != other.keyGenAlg) {
            return false;
        }
        if (Double.doubleToLongBits(this.keyNormBound) != Double.doubleToLongBits(other.keyNormBound)) {
            return false;
        }
        if (Double.doubleToLongBits(this.keyNormBoundSq) != Double.doubleToLongBits(other.keyNormBoundSq)) {
            return false;
        }
        if (Double.doubleToLongBits(this.normBound) != Double.doubleToLongBits(other.normBound)) {
            return false;
        }
        if (Double.doubleToLongBits(this.normBoundSq) != Double.doubleToLongBits(other.normBoundSq)) {
            return false;
        }
        if (this.polyType != other.polyType) {
            return false;
        }
        if (this.primeCheck != other.primeCheck) {
            return false;
        }
        if (this.q != other.q) {
            return false;
        }
        if (this.signFailTolerance != other.signFailTolerance) {
            return false;
        }
        return this.sparse == other.sparse;
    }

    public String toString() {
        DecimalFormat format = new DecimalFormat("0.00");
        StringBuilder output = new StringBuilder("SignatureParameters(N=" + this.N + " q=" + this.q);
        if (this.polyType == 0) {
            output.append(" polyType=SIMPLE d=" + this.d);
        } else {
            output.append(" polyType=PRODUCT d1=" + this.d1 + " d2=" + this.d2 + " d3=" + this.d3);
        }
        output.append(" B=" + this.B + " basisType=" + this.basisType + " beta=" + format.format(this.beta) + " normBound=" + format.format(this.normBound) + " keyNormBound=" + format.format(this.keyNormBound) + " prime=" + this.primeCheck + " sparse=" + this.sparse + " keyGenAlg=" + this.keyGenAlg + " hashAlg=" + this.hashAlg + ")");
        return output.toString();
    }
}
