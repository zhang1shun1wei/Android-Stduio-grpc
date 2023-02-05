package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.SRP6Group;
import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsMAC;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6VerifierGenerator;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRPConfig;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.math.BigInteger;

public class SimulatedTlsSRPIdentityManager implements TlsSRPIdentityManager {
    private static final byte[] PREFIX_PASSWORD = Strings.toByteArray("password");
    private static final byte[] PREFIX_SALT = Strings.toByteArray("salt");
    protected SRP6Group group;
    protected TlsMAC mac;
    protected TlsSRP6VerifierGenerator verifierGenerator;

    public static SimulatedTlsSRPIdentityManager getRFC5054Default(TlsCrypto crypto, SRP6Group group2, byte[] seedKey) throws IOException {
        TlsMAC mac2 = crypto.createHMAC(2);
        mac2.setKey(seedKey, 0, seedKey.length);
        TlsSRPConfig srpConfig = new TlsSRPConfig();
        srpConfig.setExplicitNG(new BigInteger[]{group2.getN(), group2.getG()});
        return new SimulatedTlsSRPIdentityManager(group2, crypto.createSRP6VerifierGenerator(srpConfig), mac2);
    }

    public SimulatedTlsSRPIdentityManager(SRP6Group group2, TlsSRP6VerifierGenerator verifierGenerator2, TlsMAC mac2) {
        this.group = group2;
        this.verifierGenerator = verifierGenerator2;
        this.mac = mac2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsSRPIdentityManager
    public TlsSRPLoginParameters getLoginParameters(byte[] identity) {
        this.mac.update(PREFIX_SALT, 0, PREFIX_SALT.length);
        this.mac.update(identity, 0, identity.length);
        byte[] salt = this.mac.calculateMAC();
        this.mac.update(PREFIX_PASSWORD, 0, PREFIX_PASSWORD.length);
        this.mac.update(identity, 0, identity.length);
        BigInteger verifier = this.verifierGenerator.generateVerifier(salt, identity, this.mac.calculateMAC());
        TlsSRPConfig srpConfig = new TlsSRPConfig();
        srpConfig.setExplicitNG(new BigInteger[]{this.group.getN(), this.group.getG()});
        return new TlsSRPLoginParameters(identity, srpConfig, verifier, salt);
    }
}
