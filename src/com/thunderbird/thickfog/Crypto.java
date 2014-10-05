package com.thunderbird.thickfog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.io.OutputStream;

// -- Base ancestor for all encryption classes
public abstract class Crypto {
  public static int BLOCK_SIZE = 16;    // The default block size
  byte[] key = null;                    // The key
  byte[] IV = null;                     // The initialization vector needed by the CBC mode

  Cipher encryptCipher = null;
  Cipher decryptCipher = null;

  public void resetCiphers() {
    encryptCipher = null;
    decryptCipher = null;
  }

  public abstract void initCiphers();
  public abstract void encrypt(InputStream is, OutputStream os);
  public abstract void decrypt(InputStream is, OutputStream os);

  protected Crypto(byte[] pass, byte[] iv) {
    // get the key and the IV
    key = new byte[pass.length];
    System.arraycopy(pass, 0, key, 0, pass.length);
    IV = new byte[BLOCK_SIZE];
    if (iv != null) System.arraycopy(iv, 0, IV, 0, iv.length);
  }

  public byte[] getKey() {
    return key;
  }

  public void setKey(byte[] key) {
    this.key = key;
  }

  public byte[] getIV() {
    return IV;
  }

  public void setIV(byte[] IV) {
    this.IV = IV;
  }
}