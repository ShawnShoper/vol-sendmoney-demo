package com.example.demo.vol;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public final class Crypto {

  private static final ThreadLocal<SecureRandom> secureRandom = ThreadLocal.withInitial(SecureRandom::new);

  private Crypto() {
  } //never

  private static MessageDigest getMessageDigest(String algorithm) {
    try {
      return MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e.getMessage(), e);
    }
  }

  public static MessageDigest sha256() {
    return getMessageDigest("SHA-256");
  }

  public static byte[] ripemd160(byte[] data) {
    RIPEMD160Digest d = new RIPEMD160Digest();
    d.update(data, 0, data.length);
    byte[] ret = new byte[d.getDigestSize()];
    d.doFinal(ret, 0);
    return ret;
  }

  public static byte[] getPublicKey(String secretPhrase) {
    byte[] publicKey = new byte[32];
    Curve25519.keygen(publicKey, null, Crypto.sha256().digest(Convert.toBytes(secretPhrase)));

    return publicKey;
  }

  public static byte[] getPrivateKey(String secretPhrase) {
    byte[] s = Crypto.sha256().digest(Convert.toBytes(secretPhrase));
    Curve25519.clamp(s);
    return s;
  }

  public static void curve(byte[] Z, byte[] k, byte[] P) {
    Curve25519.curve(Z, k, P);
  }

  public static byte[] sign(byte[] message, String secretPhrase) {

    byte[] P = new byte[32];
    byte[] s = new byte[32];
    MessageDigest digest = Crypto.sha256();
    Curve25519.keygen(P, s, digest.digest(Convert.toBytes(secretPhrase)));
    byte[] m = digest.digest(message);

    digest.update(m);
    byte[] x = digest.digest(s);

    byte[] Y = new byte[32];
    Curve25519.keygen(Y, null, x);

    digest.update(m);
    byte[] h = digest.digest(Y);

    byte[] v = new byte[32];
    Curve25519.sign(v, h, x, s);

    byte[] signature = new byte[64];
    System.arraycopy(v, 0, signature, 0, 32);
    System.arraycopy(h, 0, signature, 32, 32);

    return signature;
  }

  public static boolean verify(byte[] signature, byte[] message, byte[] publicKey, boolean enforceCanonical) {

    if (enforceCanonical && !Curve25519.isCanonicalSignature(signature)) {
      return false;
    }

    if (enforceCanonical && !Curve25519.isCanonicalPublicKey(publicKey)) {
      return false;
    }

    byte[] Y = new byte[32];
    byte[] v = new byte[32];
    System.arraycopy(signature, 0, v, 0, 32);
    byte[] h = new byte[32];
    System.arraycopy(signature, 32, h, 0, 32);
    Curve25519.verify(Y, v, h, publicKey);

    MessageDigest digest = Crypto.sha256();
    byte[] m = digest.digest(message);
    digest.update(m);
    byte[] h2 = digest.digest(Y);

    return Arrays.equals(h, h2);
  }

  public static byte[] signTransactionBytes(byte[] unsignedTransactionBytes, byte[] signature) {
    byte[] ret = new byte[unsignedTransactionBytes.length + signature.length];
    System.arraycopy(unsignedTransactionBytes, 0, ret, 0, unsignedTransactionBytes.length);
    System.arraycopy(signature, 0, ret, 96, signature.length);
    return ret;
  }
  

  public static String rsEncode(long id) {
    return ReedSolomon.encode(id);
  }

  public static long rsDecode(String rsString) {
    rsString = rsString.toUpperCase();
    try {
      long id = ReedSolomon.decode(rsString);
      if (!rsString.equals(ReedSolomon.encode(id))) {
        throw new RuntimeException("ERROR: Reed-Solomon decoding of " + rsString + " not reversible, decoded to " + id);
      }
      return id;
    } catch (ReedSolomon.DecodeException | NumberFormatException e) {
      throw new RuntimeException(e.toString(), e);
    }
  }

}
