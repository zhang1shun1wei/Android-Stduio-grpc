package com.mi.car.jsse.easysec.jcajce.provider.asymmetric.elgamal;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ElGamalParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPublicKeyParameters;
import com.mi.car.jsse.easysec.jce.interfaces.ElGamalPrivateKey;
import com.mi.car.jsse.easysec.jce.interfaces.ElGamalPublicKey;

/**
 * utility class for converting jce/jca ElGamal objects
 * objects into their com.mi.car.jsse.easysec.crypto counterparts.
 */
public class ElGamalUtil
{
    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof ElGamalPublicKey)
        {
            ElGamalPublicKey    k = (ElGamalPublicKey)key;

            return new ElGamalPublicKeyParameters(k.getY(),
                new ElGamalParameters(k.getParameters().getP(), k.getParameters().getG()));
        }
        else if (key instanceof DHPublicKey)
        {
            DHPublicKey    k = (DHPublicKey)key;

            return new ElGamalPublicKeyParameters(k.getY(),
                new ElGamalParameters(k.getParams().getP(), k.getParams().getG()));
        }

        throw new InvalidKeyException("can't identify public key for El Gamal.");
    }

    static public AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof ElGamalPrivateKey)
        {
            ElGamalPrivateKey    k = (ElGamalPrivateKey)key;

            return new ElGamalPrivateKeyParameters(k.getX(),
                new ElGamalParameters(k.getParameters().getP(), k.getParameters().getG()));
        }
        else if (key instanceof DHPrivateKey)
        {
            DHPrivateKey    k = (DHPrivateKey)key;

            return new ElGamalPrivateKeyParameters(k.getX(),
                new ElGamalParameters(k.getParams().getP(), k.getParams().getG()));
        }
                        
        throw new InvalidKeyException("can't identify private key for El Gamal.");
    }
}
