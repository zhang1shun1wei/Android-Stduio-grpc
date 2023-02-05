package com.mi.car.jsse.easysec.jcajce.provider.asymmetric.dh;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

import javax.crypto.spec.DHParameterSpec;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.generators.DHBasicKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.generators.DHParametersGenerator;
import com.mi.car.jsse.easysec.crypto.params.DHKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import com.mi.car.jsse.easysec.jcajce.spec.DHDomainParameterSpec;
import com.mi.car.jsse.easysec.jce.provider.EasysecProvider;
import com.mi.car.jsse.easysec.util.Integers;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Hashtable params = new Hashtable();
    private static Object    lock = new Object();

    DHKeyGenerationParameters param;
    DHBasicKeyPairGenerator engine = new DHBasicKeyPairGenerator();
    int strength = 2048;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("DH");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
        this.initialised = false;
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof DHParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec");
        }
        DHParameterSpec dhParams = (DHParameterSpec)params;

        try
        {
            param = convertParams(random, dhParams);
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
        
        engine.init(param);
        initialised = true;
    }

    private DHKeyGenerationParameters convertParams(SecureRandom random, DHParameterSpec dhParams)
    {
        if (dhParams instanceof DHDomainParameterSpec)
        {
            return new DHKeyGenerationParameters(random, ((DHDomainParameterSpec)dhParams).getDomainParameters());
        }
        return new DHKeyGenerationParameters(random, new DHParameters(dhParams.getP(), dhParams.getG(), null, dhParams.getL()));
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            Integer paramStrength = Integers.valueOf(strength);

            if (params.containsKey(paramStrength))
            {
                param = (DHKeyGenerationParameters)params.get(paramStrength);
            }
            else
            {
                DHParameterSpec dhParams = EasysecProvider.CONFIGURATION.getDHDefaultParameters(strength);

                if (dhParams != null)
                {   
                    param = convertParams(random, dhParams);
                }
                else
                {
                    synchronized (lock)
                    {
                        // we do the check again in case we were blocked by a generator for
                        // our key size.
                        if (params.containsKey(paramStrength))
                        {
                            param = (DHKeyGenerationParameters)params.get(paramStrength);
                        }
                        else
                        {

                            DHParametersGenerator pGen = new DHParametersGenerator();

                            pGen.init(strength, PrimeCertaintyCalculator.getDefaultCertainty(strength), random);

                            param = new DHKeyGenerationParameters(random, pGen.generateParameters());

                            params.put(paramStrength, param);
                        }
                    }
                }
            }

            engine.init(param);

            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        DHPublicKeyParameters pub = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters priv = (DHPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCDHPublicKey(pub), new BCDHPrivateKey(priv));
    }
}
