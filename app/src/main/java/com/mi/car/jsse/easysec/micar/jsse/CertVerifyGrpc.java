package com.mi.car.jsse.easysec.micar.jsse;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.42.1)",
    comments = "Source: test.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class CertVerifyGrpc {

  private CertVerifyGrpc() {}

  public static final String SERVICE_NAME = "jsse.CertVerify";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<com.google.protobuf.Empty,
      IdentityCertParam> getGetIdentityCertMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "getIdentityCert",
      requestType = com.google.protobuf.Empty.class,
      responseType = IdentityCertParam.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.google.protobuf.Empty,
      IdentityCertParam> getGetIdentityCertMethod() {
    io.grpc.MethodDescriptor<com.google.protobuf.Empty, IdentityCertParam> getGetIdentityCertMethod;
    if ((getGetIdentityCertMethod = CertVerifyGrpc.getGetIdentityCertMethod) == null) {
      synchronized (CertVerifyGrpc.class) {
        if ((getGetIdentityCertMethod = CertVerifyGrpc.getGetIdentityCertMethod) == null) {
          CertVerifyGrpc.getGetIdentityCertMethod = getGetIdentityCertMethod =
              io.grpc.MethodDescriptor.<com.google.protobuf.Empty, IdentityCertParam>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "getIdentityCert"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.lite.ProtoLiteUtils.marshaller(
                  com.google.protobuf.Empty.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.lite.ProtoLiteUtils.marshaller(
                  IdentityCertParam.getDefaultInstance()))
              .build();
        }
      }
    }
    return getGetIdentityCertMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.google.protobuf.Empty,
      X509CertChainParam> getGetX509CertChainMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "getX509CertChain",
      requestType = com.google.protobuf.Empty.class,
      responseType = X509CertChainParam.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.google.protobuf.Empty,
      X509CertChainParam> getGetX509CertChainMethod() {
    io.grpc.MethodDescriptor<com.google.protobuf.Empty, X509CertChainParam> getGetX509CertChainMethod;
    if ((getGetX509CertChainMethod = CertVerifyGrpc.getGetX509CertChainMethod) == null) {
      synchronized (CertVerifyGrpc.class) {
        if ((getGetX509CertChainMethod = CertVerifyGrpc.getGetX509CertChainMethod) == null) {
          CertVerifyGrpc.getGetX509CertChainMethod = getGetX509CertChainMethod =
              io.grpc.MethodDescriptor.<com.google.protobuf.Empty, X509CertChainParam>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "getX509CertChain"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.lite.ProtoLiteUtils.marshaller(
                  com.google.protobuf.Empty.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.lite.ProtoLiteUtils.marshaller(
                  X509CertChainParam.getDefaultInstance()))
              .build();
        }
      }
    }
    return getGetX509CertChainMethod;
  }

  private static volatile io.grpc.MethodDescriptor<generateSignatureParam,
      generateSignatureParam> getGenerateSignatureMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "generateSignature",
      requestType = generateSignatureParam.class,
      responseType = generateSignatureParam.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<generateSignatureParam,
      generateSignatureParam> getGenerateSignatureMethod() {
    io.grpc.MethodDescriptor<generateSignatureParam, generateSignatureParam> getGenerateSignatureMethod;
    if ((getGenerateSignatureMethod = CertVerifyGrpc.getGenerateSignatureMethod) == null) {
      synchronized (CertVerifyGrpc.class) {
        if ((getGenerateSignatureMethod = CertVerifyGrpc.getGenerateSignatureMethod) == null) {
          CertVerifyGrpc.getGenerateSignatureMethod = getGenerateSignatureMethod =
              io.grpc.MethodDescriptor.<generateSignatureParam, generateSignatureParam>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "generateSignature"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.lite.ProtoLiteUtils.marshaller(
                  generateSignatureParam.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.lite.ProtoLiteUtils.marshaller(
                  generateSignatureParam.getDefaultInstance()))
              .build();
        }
      }
    }
    return getGenerateSignatureMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static CertVerifyStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<CertVerifyStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<CertVerifyStub>() {
        @Override
        public CertVerifyStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new CertVerifyStub(channel, callOptions);
        }
      };
    return CertVerifyStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static CertVerifyBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<CertVerifyBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<CertVerifyBlockingStub>() {
        @Override
        public CertVerifyBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new CertVerifyBlockingStub(channel, callOptions);
        }
      };
    return CertVerifyBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static CertVerifyFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<CertVerifyFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<CertVerifyFutureStub>() {
        @Override
        public CertVerifyFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new CertVerifyFutureStub(channel, callOptions);
        }
      };
    return CertVerifyFutureStub.newStub(factory, channel);
  }

  /**
   */
  public static abstract class CertVerifyImplBase implements io.grpc.BindableService {

    /**
     */
    public void getIdentityCert(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<IdentityCertParam> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetIdentityCertMethod(), responseObserver);
    }

    /**
     */
    public void getX509CertChain(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<X509CertChainParam> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetX509CertChainMethod(), responseObserver);
    }

    /**
     */
    public void generateSignature(generateSignatureParam request,
                                  io.grpc.stub.StreamObserver<generateSignatureParam> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGenerateSignatureMethod(), responseObserver);
    }

    @Override public final io.grpc.ServerServiceDefinition bindService() {
      return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
          .addMethod(
            getGetIdentityCertMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                com.google.protobuf.Empty,
                IdentityCertParam>(
                  this, METHODID_GET_IDENTITY_CERT)))
          .addMethod(
            getGetX509CertChainMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                com.google.protobuf.Empty,
                X509CertChainParam>(
                  this, METHODID_GET_X509CERT_CHAIN)))
          .addMethod(
            getGenerateSignatureMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                generateSignatureParam,
                generateSignatureParam>(
                  this, METHODID_GENERATE_SIGNATURE)))
          .build();
    }
  }

  /**
   */
  public static final class CertVerifyStub extends io.grpc.stub.AbstractAsyncStub<CertVerifyStub> {
    private CertVerifyStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @Override
    protected CertVerifyStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new CertVerifyStub(channel, callOptions);
    }

    /**
     */
    public void getIdentityCert(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<IdentityCertParam> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetIdentityCertMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getX509CertChain(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<X509CertChainParam> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetX509CertChainMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void generateSignature(generateSignatureParam request,
                                  io.grpc.stub.StreamObserver<generateSignatureParam> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGenerateSignatureMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   */
  public static final class CertVerifyBlockingStub extends io.grpc.stub.AbstractBlockingStub<CertVerifyBlockingStub> {
    private CertVerifyBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @Override
    protected CertVerifyBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new CertVerifyBlockingStub(channel, callOptions);
    }

    /**
     */
    public IdentityCertParam getIdentityCert(com.google.protobuf.Empty request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetIdentityCertMethod(), getCallOptions(), request);
    }

    /**
     */
    public X509CertChainParam getX509CertChain(com.google.protobuf.Empty request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetX509CertChainMethod(), getCallOptions(), request);
    }

    /**
     */
    public generateSignatureParam generateSignature(generateSignatureParam request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGenerateSignatureMethod(), getCallOptions(), request);
    }
  }

  /**
   */
  public static final class CertVerifyFutureStub extends io.grpc.stub.AbstractFutureStub<CertVerifyFutureStub> {
    private CertVerifyFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @Override
    protected CertVerifyFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new CertVerifyFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<IdentityCertParam> getIdentityCert(
        com.google.protobuf.Empty request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetIdentityCertMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<X509CertChainParam> getX509CertChain(
        com.google.protobuf.Empty request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetX509CertChainMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<generateSignatureParam> generateSignature(
        generateSignatureParam request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGenerateSignatureMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_GET_IDENTITY_CERT = 0;
  private static final int METHODID_GET_X509CERT_CHAIN = 1;
  private static final int METHODID_GENERATE_SIGNATURE = 2;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final CertVerifyImplBase serviceImpl;
    private final int methodId;

    MethodHandlers(CertVerifyImplBase serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_GET_IDENTITY_CERT:
          serviceImpl.getIdentityCert((com.google.protobuf.Empty) request,
              (io.grpc.stub.StreamObserver<IdentityCertParam>) responseObserver);
          break;
        case METHODID_GET_X509CERT_CHAIN:
          serviceImpl.getX509CertChain((com.google.protobuf.Empty) request,
              (io.grpc.stub.StreamObserver<X509CertChainParam>) responseObserver);
          break;
        case METHODID_GENERATE_SIGNATURE:
          serviceImpl.generateSignature((generateSignatureParam) request,
              (io.grpc.stub.StreamObserver<generateSignatureParam>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @Override
    @SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (CertVerifyGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .addMethod(getGetIdentityCertMethod())
              .addMethod(getGetX509CertChainMethod())
              .addMethod(getGenerateSignatureMethod())
              .build();
        }
      }
    }
    return result;
  }
}
