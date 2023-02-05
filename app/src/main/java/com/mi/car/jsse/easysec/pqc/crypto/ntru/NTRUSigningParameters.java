package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DecimalFormat;

public class NTRUSigningParameters implements Cloneable {
    public int B;
    public int N;
    double beta;
    public double betaSq;
    int bitsF = 6;
    public int d;
    public int d1;
    public int d2;
    public int d3;
    public Digest hashAlg;
    double normBound;
    public double normBoundSq;
    public int q;
    public int signFailTolerance = 100;

    public NTRUSigningParameters(int N2, int q2, int d4, int B2, double beta2, double normBound2, Digest hashAlg2) {
        this.N = N2;
        this.q = q2;
        this.d = d4;
        this.B = B2;
        this.beta = beta2;
        this.normBound = normBound2;
        this.hashAlg = hashAlg2;
        init();
    }

    public NTRUSigningParameters(int N2, int q2, int d12, int d22, int d32, int B2, double beta2, double normBound2, double keyNormBound, Digest hashAlg2) {
        this.N = N2;
        this.q = q2;
        this.d1 = d12;
        this.d2 = d22;
        this.d3 = d32;
        this.B = B2;
        this.beta = beta2;
        this.normBound = normBound2;
        this.hashAlg = hashAlg2;
        init();
    }

    private void init() {
        this.betaSq = this.beta * this.beta;
        this.normBoundSq = this.normBound * this.normBound;
    }

    public NTRUSigningParameters(InputStream is) throws IOException {
        DataInputStream dis = new DataInputStream(is);
        this.N = dis.readInt();
        this.q = dis.readInt();
        this.d = dis.readInt();
        this.d1 = dis.readInt();
        this.d2 = dis.readInt();
        this.d3 = dis.readInt();
        this.B = dis.readInt();
        this.beta = dis.readDouble();
        this.normBound = dis.readDouble();
        this.signFailTolerance = dis.readInt();
        this.bitsF = dis.readInt();
        String alg = dis.readUTF();
        if ("SHA-512".equals(alg)) {
            this.hashAlg = new SHA512Digest();
        } else if ("SHA-256".equals(alg)) {
            this.hashAlg = new SHA256Digest();
        }
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
        dos.writeDouble(this.beta);
        dos.writeDouble(this.normBound);
        dos.writeInt(this.signFailTolerance);
        dos.writeInt(this.bitsF);
        dos.writeUTF(this.hashAlg.getAlgorithmName());
    }

    @Override // java.lang.Object
    public NTRUSigningParameters clone() {
        return new NTRUSigningParameters(this.N, this.q, this.d, this.B, this.beta, this.normBound, this.hashAlg);
    }

    public int hashCode() {
        int result = ((this.B + 31) * 31) + this.N;
        long temp = Double.doubleToLongBits(this.beta);
        int result2 = (result * 31) + ((int) ((temp >>> 32) ^ temp));
        long temp2 = Double.doubleToLongBits(this.betaSq);
        int result3 = (((((((((((((result2 * 31) + ((int) ((temp2 >>> 32) ^ temp2))) * 31) + this.bitsF) * 31) + this.d) * 31) + this.d1) * 31) + this.d2) * 31) + this.d3) * 31) + (this.hashAlg == null ? 0 : this.hashAlg.getAlgorithmName().hashCode());
        long temp3 = Double.doubleToLongBits(this.normBound);
        int result4 = (result3 * 31) + ((int) ((temp3 >>> 32) ^ temp3));
        long temp4 = Double.doubleToLongBits(this.normBoundSq);
        return (((((result4 * 31) + ((int) ((temp4 >>> 32) ^ temp4))) * 31) + this.q) * 31) + this.signFailTolerance;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof NTRUSigningParameters)) {
            return false;
        }
        NTRUSigningParameters other = (NTRUSigningParameters) obj;
        if (this.B != other.B) {
            return false;
        }
        if (this.N != other.N) {
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
        if (Double.doubleToLongBits(this.normBound) != Double.doubleToLongBits(other.normBound)) {
            return false;
        }
        if (Double.doubleToLongBits(this.normBoundSq) != Double.doubleToLongBits(other.normBoundSq)) {
            return false;
        }
        if (this.q != other.q) {
            return false;
        }
        return this.signFailTolerance == other.signFailTolerance;
    }

    public String toString() {
        DecimalFormat format = new DecimalFormat("0.00");
        StringBuilder output = new StringBuilder("SignatureParameters(N=" + this.N + " q=" + this.q);
        output.append(" B=" + this.B + " beta=" + format.format(this.beta) + " normBound=" + format.format(this.normBound) + " hashAlg=" + this.hashAlg + ")");
        return output.toString();
    }
}
