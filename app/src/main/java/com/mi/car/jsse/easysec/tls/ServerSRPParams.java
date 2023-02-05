package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

public class ServerSRPParams {
    protected BigInteger B;
    protected BigInteger N;
    protected BigInteger g;
    protected byte[] s;

    public ServerSRPParams(BigInteger N2, BigInteger g2, byte[] s2, BigInteger B2) {
        this.N = N2;
        this.g = g2;
        this.s = Arrays.clone(s2);
        this.B = B2;
    }

    public BigInteger getB() {
        return this.B;
    }

    public BigInteger getG() {
        return this.g;
    }

    public BigInteger getN() {
        return this.N;
    }

    public byte[] getS() {
        return this.s;
    }

    public void encode(OutputStream output) throws IOException {
        TlsSRPUtils.writeSRPParameter(this.N, output);
        TlsSRPUtils.writeSRPParameter(this.g, output);
        TlsUtils.writeOpaque8(this.s, output);
        TlsSRPUtils.writeSRPParameter(this.B, output);
    }

    public static ServerSRPParams parse(InputStream input) throws IOException {
        return new ServerSRPParams(TlsSRPUtils.readSRPParameter(input), TlsSRPUtils.readSRPParameter(input), TlsUtils.readOpaque8(input, 1), TlsSRPUtils.readSRPParameter(input));
    }
}
