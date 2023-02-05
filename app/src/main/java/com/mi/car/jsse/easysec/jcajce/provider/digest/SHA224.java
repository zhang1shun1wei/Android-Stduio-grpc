package com.mi.car.jsse.easysec.jcajce.provider.digest;

import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.CipherKeyGenerator;
import com.mi.car.jsse.easysec.crypto.digests.SHA224Digest;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseMac;

public class SHA224
{
    private SHA224()
    {

    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new SHA224Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new SHA224Digest((SHA224Digest)digest);

            return d;
        }
    }

    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new SHA224Digest()));
        }
    }

    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACSHA224", 224, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA224.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.SHA-224", PREFIX + "$Digest");
            provider.addAlgorithm("Alg.Alias.MessageDigest.SHA224", "SHA-224");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha224, "SHA-224");

            provider.addAlgorithm("Mac.PBEWITHHMACSHA224", PREFIX + "$HashMac");

            addHMACAlgorithm(provider, "SHA224", PREFIX + "$HashMac",  PREFIX + "$KeyGenerator");
            addHMACAlias(provider, "SHA224", PKCSObjectIdentifiers.id_hmacWithSHA224);

        }
    }
}
