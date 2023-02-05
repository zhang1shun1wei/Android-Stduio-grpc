package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.util.Encodable;
import java.io.IOException;

public abstract class LMSKeyParameters extends AsymmetricKeyParameter implements Encodable {
    @Override // com.mi.car.jsse.easysec.util.Encodable
    public abstract byte[] getEncoded() throws IOException;

    protected LMSKeyParameters(boolean isPrivateKey) {
        super(isPrivateKey);
    }
}
