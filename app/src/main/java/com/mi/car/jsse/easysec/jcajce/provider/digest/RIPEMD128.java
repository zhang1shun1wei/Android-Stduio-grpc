package com.mi.car.jsse.easysec.jcajce.provider.digest;

import com.mi.car.jsse.easysec.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.CipherKeyGenerator;
import com.mi.car.jsse.easysec.crypto.digests.RIPEMD128Digest;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseMac;

public class RIPEMD128
{
    private RIPEMD128()
    {

    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new RIPEMD128Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new RIPEMD128Digest((RIPEMD128Digest)digest);

            return d;
        }
    }

    /**
     * RIPEMD128 HashMac
     */
    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new RIPEMD128Digest()));
        }
    }

    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACRIPEMD128", 128, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = RIPEMD128.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.RIPEMD128", PREFIX + "$Digest");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");            

            addHMACAlgorithm(provider, "RIPEMD128", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
        }
    }
}
