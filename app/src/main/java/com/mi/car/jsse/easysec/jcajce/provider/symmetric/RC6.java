package com.mi.car.jsse.easysec.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherKeyGenerator;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.engines.RC6Engine;
import com.mi.car.jsse.easysec.crypto.generators.Poly1305KeyGenerator;
import com.mi.car.jsse.easysec.crypto.macs.GMac;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.GCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.OFBBlockCipher;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseBlockCipher;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseMac;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BlockCipherProvider;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class RC6
{
    private RC6()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new RC6Engine();
                }
            });
        }
    }

    public static class CBC
       extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new RC6Engine()), 128);
        }
    }

    static public class CFB
        extends BaseBlockCipher
    {
        public CFB()
        {
            super(new BufferedBlockCipher(new CFBBlockCipher(new RC6Engine(), 128)), 128);
        }
    }

    static public class OFB
        extends BaseBlockCipher
    {
        public OFB()
        {
            super(new BufferedBlockCipher(new OFBBlockCipher(new RC6Engine(), 128)), 128);
        }
    }

    public static class GMAC
        extends BaseMac
    {
        public GMAC()
        {
            super(new GMac(new GCMBlockCipher(new RC6Engine())));
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new com.mi.car.jsse.easysec.crypto.macs.Poly1305(new RC6Engine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-RC6", 256, new Poly1305KeyGenerator());
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("RC6", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC6 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[]  iv = new byte[16];

            if (random == null)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = createParametersInstance("RC6");
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "RC6 IV";
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = RC6.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.RC6", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.RC6", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.RC6", PREFIX + "$AlgParams");

            addGMacAlgorithm(provider, "RC6", PREFIX + "$GMAC", PREFIX + "$KeyGen");
            addPoly1305Algorithm(provider, "RC6", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
        }
    }
}
