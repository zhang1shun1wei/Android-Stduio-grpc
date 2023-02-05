package com.mi.car.jsse.easysec.crypto.ec;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;

public class ECElGamalDecryptor implements ECDecryptor {
    private ECPrivateKeyParameters key;

    @Override // com.mi.car.jsse.easysec.crypto.ec.ECDecryptor
    public void init(CipherParameters param) {
        if (!(param instanceof ECPrivateKeyParameters)) {
            throw new IllegalArgumentException("ECPrivateKeyParameters are required for decryption.");
        }
        this.key = (ECPrivateKeyParameters) param;
    }

    @Override // com.mi.car.jsse.easysec.crypto.ec.ECDecryptor
    public ECPoint decrypt(ECPair pair) {
        if (this.key == null) {
            throw new IllegalStateException("ECElGamalDecryptor not initialised");
        }
        ECCurve curve = this.key.getParameters().getCurve();
        return ECAlgorithms.cleanPoint(curve, pair.getY()).subtract(ECAlgorithms.cleanPoint(curve, pair.getX()).multiply(this.key.getD())).normalize();
    }
}
