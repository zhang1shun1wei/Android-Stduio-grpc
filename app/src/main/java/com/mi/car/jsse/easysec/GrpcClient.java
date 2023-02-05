package com.mi.car.jsse.easysec;

import com.google.protobuf.ByteString;

import com.mi.car.jsse.easysec.micar.jsse.CertVerifyGrpc;
import com.mi.car.jsse.easysec.micar.jsse.IdentityCertParam;
import com.mi.car.jsse.easysec.micar.jsse.X509CertChainParam;
import com.mi.car.jsse.easysec.micar.jsse.generateSignatureParam;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class GrpcClient {
    private volatile static GrpcClient singleton;
    private CertVerifyGrpc.CertVerifyBlockingStub mCertChainBlockingStub;

    private GrpcClient() {
        String host = "192.168.8.1";
        int port = 50051;
        ManagedChannel channel = ManagedChannelBuilder.forAddress(host, port).usePlaintext().build();
        mCertChainBlockingStub = CertVerifyGrpc.newBlockingStub(channel);
    }

    public static GrpcClient getSingleton() {
        if (singleton == null) {
            synchronized (GrpcClient.class) {
                if (singleton == null) {
                    singleton = new GrpcClient();
                }
            }
        }
        return singleton;
    }

    public String getIdentityCert() {
        if (mCertChainBlockingStub == null) {
            return null;
        }
        IdentityCertParam para21 = mCertChainBlockingStub.getIdentityCert(null);
        String cert = para21.getCert();
        return cert;
    }

    public String getX509CertChain() {
        if (mCertChainBlockingStub == null) {
            return null;
        }
        X509CertChainParam x509CertChain = mCertChainBlockingStub.getX509CertChain(null);
        String chain = x509CertChain.getChain();
        return chain;
    }

    public byte[] generateSignature(byte[] hash) {
        if (hash == null || mCertChainBlockingStub == null) {
            return null;
        }
        generateSignatureParam para2 = generateSignatureParam.newBuilder().setSignature(ByteString.copyFrom(hash)).build();
        generateSignatureParam value = mCertChainBlockingStub.generateSignature(para2);
        byte[] bytes = value.getSignature().toByteArray();
        return bytes;
    }
}