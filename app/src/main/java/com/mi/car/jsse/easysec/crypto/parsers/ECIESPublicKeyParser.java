package com.mi.car.jsse.easysec.crypto.parsers;

import com.mi.car.jsse.easysec.crypto.KeyParser;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.IOException;
import java.io.InputStream;

public class ECIESPublicKeyParser implements KeyParser {
    private ECDomainParameters ecParams;

    public ECIESPublicKeyParser(ECDomainParameters ecParams2) {
        this.ecParams = ecParams2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.KeyParser
    public AsymmetricKeyParameter readKey(InputStream stream) throws IOException {
        byte[] V;
        int first = stream.read();
        switch (first) {
            case 0:
                throw new IOException("Sender's public key invalid.");
            case 1:
            case 5:
            default:
                throw new IOException("Sender's public key has invalid point encoding 0x" + Integer.toString(first, 16));
            case 2:
            case 3:
                V = new byte[(((this.ecParams.getCurve().getFieldSize() + 7) / 8) + 1)];
                break;
            case 4:
            case 6:
            case 7:
                V = new byte[((((this.ecParams.getCurve().getFieldSize() + 7) / 8) * 2) + 1)];
                break;
        }
        V[0] = (byte) first;
        Streams.readFully(stream, V, 1, V.length - 1);
        return new ECPublicKeyParameters(this.ecParams.getCurve().decodePoint(V), this.ecParams);
    }
}
