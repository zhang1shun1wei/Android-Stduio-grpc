package com.mi.car.jsse.easysec.crypto.parsers;

import com.mi.car.jsse.easysec.crypto.KeyParser;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

public class DHIESPublicKeyParser implements KeyParser {
    private DHParameters dhParams;

    public DHIESPublicKeyParser(DHParameters dhParams2) {
        this.dhParams = dhParams2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.KeyParser
    public AsymmetricKeyParameter readKey(InputStream stream) throws IOException {
        byte[] V = new byte[((this.dhParams.getP().bitLength() + 7) / 8)];
        Streams.readFully(stream, V, 0, V.length);
        return new DHPublicKeyParameters(new BigInteger(1, V), this.dhParams);
    }
}
