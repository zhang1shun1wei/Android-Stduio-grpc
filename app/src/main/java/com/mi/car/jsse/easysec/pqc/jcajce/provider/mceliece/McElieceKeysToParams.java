package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class McElieceKeysToParams {
    public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key) throws InvalidKeyException {
        if (key instanceof BCMcEliecePublicKey) {
            return ((BCMcEliecePublicKey) key).getKeyParams();
        }
        throw new InvalidKeyException("can't identify McEliece public key: " + key.getClass().getName());
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key) throws InvalidKeyException {
        if (key instanceof BCMcEliecePrivateKey) {
            BCMcEliecePrivateKey k = (BCMcEliecePrivateKey) key;
            return new McEliecePrivateKeyParameters(k.getN(), k.getK(), k.getField(), k.getGoppaPoly(), k.getP1(), k.getP2(), k.getSInv());
        }
        throw new InvalidKeyException("can't identify McEliece private key.");
    }
}
