package com.thunderbird.thickfog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;

// -- Base ancestor for all encryption classes
public abstract class Crypto {
  final private static Logger LOGGER = LoggerFactory.getLogger(Utils.class);
  public static int BLOCK_SIZE = 16;    // The default block size
  byte[] key = null;                    // The key
  byte[] IV = null;                     // The initialization vector needed by the CBC mode

  Cipher encryptCipher = null;
  Cipher decryptCipher = null;

  public void resetCiphers() {
    encryptCipher = null;
    decryptCipher = null;
  }

  public abstract void initCiphers() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException;
  public abstract void encrypt(InputStream is, OutputStream os) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException;
  public abstract void decrypt(InputStream is, OutputStream os) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException;

  protected Crypto(byte[] pass, byte[] iv) {
    // get the key and the IV
    key = new byte[pass.length];
    System.arraycopy(pass, 0, key, 0, pass.length);
    IV = new byte[BLOCK_SIZE];
    System.arraycopy(iv, 0, IV, 0, iv.length);
  }

  public byte[] getIV() {
    return IV;
  }

  public void setIV(byte[] iv) {
    System.arraycopy(iv, 0, IV, 0, iv.length);
  }
}