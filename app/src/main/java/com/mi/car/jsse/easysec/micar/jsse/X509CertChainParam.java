// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: test.proto

package com.mi.car.jsse.easysec.micar.jsse;

/**
 * Protobuf type {@code jsse.X509CertChainParam}
 */
public  final class X509CertChainParam extends
    com.google.protobuf.GeneratedMessageLite<
        X509CertChainParam, X509CertChainParam.Builder> implements
    // @@protoc_insertion_point(message_implements:jsse.X509CertChainParam)
    X509CertChainParamOrBuilder {
  private X509CertChainParam() {
    chain_ = "";
  }
  public static final int CHAIN_FIELD_NUMBER = 1;
  private String chain_;
  /**
   * <code>string chain = 1;</code>
   * @return The chain.
   */
  @Override
  public String getChain() {
    return chain_;
  }
  /**
   * <code>string chain = 1;</code>
   * @return The bytes for chain.
   */
  @Override
  public com.google.protobuf.ByteString
      getChainBytes() {
    return com.google.protobuf.ByteString.copyFromUtf8(chain_);
  }
  /**
   * <code>string chain = 1;</code>
   * @param value The chain to set.
   */
  private void setChain(
      String value) {
    Class<?> valueClass = value.getClass();
  
    chain_ = value;
  }
  /**
   * <code>string chain = 1;</code>
   */
  private void clearChain() {
    
    chain_ = getDefaultInstance().getChain();
  }
  /**
   * <code>string chain = 1;</code>
   * @param value The bytes for chain to set.
   */
  private void setChainBytes(
      com.google.protobuf.ByteString value) {
    checkByteStringIsUtf8(value);
    chain_ = value.toStringUtf8();
    
  }

  public static X509CertChainParam parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data);
  }
  public static X509CertChainParam parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data, extensionRegistry);
  }
  public static X509CertChainParam parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data);
  }
  public static X509CertChainParam parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data, extensionRegistry);
  }
  public static X509CertChainParam parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data);
  }
  public static X509CertChainParam parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data, extensionRegistry);
  }
  public static X509CertChainParam parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, input);
  }
  public static X509CertChainParam parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, input, extensionRegistry);
  }
  public static X509CertChainParam parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return parseDelimitedFrom(DEFAULT_INSTANCE, input);
  }
  public static X509CertChainParam parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
  }
  public static X509CertChainParam parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, input);
  }
  public static X509CertChainParam parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, input, extensionRegistry);
  }

  public static Builder newBuilder() {
    return (Builder) DEFAULT_INSTANCE.createBuilder();
  }
  public static Builder newBuilder(X509CertChainParam prototype) {
    return (Builder) DEFAULT_INSTANCE.createBuilder(prototype);
  }

  /**
   * Protobuf type {@code jsse.X509CertChainParam}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageLite.Builder<
        X509CertChainParam, Builder> implements
      // @@protoc_insertion_point(builder_implements:jsse.X509CertChainParam)
      X509CertChainParamOrBuilder {
    // Construct using com.mi.car.jsse.easysec.micar.jsse.X509CertChainParam.newBuilder()
    private Builder() {
      super(DEFAULT_INSTANCE);
    }


    /**
     * <code>string chain = 1;</code>
     * @return The chain.
     */
    @Override
    public String getChain() {
      return instance.getChain();
    }
    /**
     * <code>string chain = 1;</code>
     * @return The bytes for chain.
     */
    @Override
    public com.google.protobuf.ByteString
        getChainBytes() {
      return instance.getChainBytes();
    }
    /**
     * <code>string chain = 1;</code>
     * @param value The chain to set.
     * @return This builder for chaining.
     */
    public Builder setChain(
        String value) {
      copyOnWrite();
      instance.setChain(value);
      return this;
    }
    /**
     * <code>string chain = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearChain() {
      copyOnWrite();
      instance.clearChain();
      return this;
    }
    /**
     * <code>string chain = 1;</code>
     * @param value The bytes for chain to set.
     * @return This builder for chaining.
     */
    public Builder setChainBytes(
        com.google.protobuf.ByteString value) {
      copyOnWrite();
      instance.setChainBytes(value);
      return this;
    }

    // @@protoc_insertion_point(builder_scope:jsse.X509CertChainParam)
  }
  @Override
  @SuppressWarnings({"unchecked", "fallthrough"})
  protected final Object dynamicMethod(
      MethodToInvoke method,
      Object arg0, Object arg1) {
    switch (method) {
      case NEW_MUTABLE_INSTANCE: {
        return new X509CertChainParam();
      }
      case NEW_BUILDER: {
        return new Builder();
      }
      case BUILD_MESSAGE_INFO: {
          Object[] objects = new Object[] {
            "chain_",
          };
          String info =
              "\u0000\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0000\u0000\u0001\u0208";
          return newMessageInfo(DEFAULT_INSTANCE, info, objects);
      }
      // fall through
      case GET_DEFAULT_INSTANCE: {
        return DEFAULT_INSTANCE;
      }
      case GET_PARSER: {
        com.google.protobuf.Parser<X509CertChainParam> parser = PARSER;
        if (parser == null) {
          synchronized (X509CertChainParam.class) {
            parser = PARSER;
            if (parser == null) {
              parser =
                  new DefaultInstanceBasedParser<X509CertChainParam>(
                      DEFAULT_INSTANCE);
              PARSER = parser;
            }
          }
        }
        return parser;
    }
    case GET_MEMOIZED_IS_INITIALIZED: {
      return (byte) 1;
    }
    case SET_MEMOIZED_IS_INITIALIZED: {
      return null;
    }
    }
    throw new UnsupportedOperationException();
  }


  // @@protoc_insertion_point(class_scope:jsse.X509CertChainParam)
  private static final X509CertChainParam DEFAULT_INSTANCE;
  static {
    X509CertChainParam defaultInstance = new X509CertChainParam();
    // New instances are implicitly immutable so no need to make
    // immutable.
    DEFAULT_INSTANCE = defaultInstance;
    com.google.protobuf.GeneratedMessageLite.registerDefaultInstance(
      X509CertChainParam.class, defaultInstance);
  }

  public static X509CertChainParam getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static volatile com.google.protobuf.Parser<X509CertChainParam> PARSER;

  public static com.google.protobuf.Parser<X509CertChainParam> parser() {
    return DEFAULT_INSTANCE.getParserForType();
  }
}

