package com.thunderbird.thickfog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

// -- ECB encryption class, use for short data (file name, manifest file)
public class Crypto_AES_CBC extends Crypto {
  final private static Logger LOGGER = LoggerFactory.getLogger(Pipe.class);

  public Crypto_AES_CBC(byte[] pass, byte[] iv) {
    super(pass, iv);
  }

  @Override
  public void initCiphers() {
    try {
      // -- Init Encryptor
      encryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
      SecretKey keyValue = new SecretKeySpec(key, "AES");
      AlgorithmParameterSpec IVspec = new IvParameterSpec(IV);
      encryptCipher.init(Cipher.ENCRYPT_MODE, keyValue, IVspec);

      // -- Init Decryptor
      decryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
      decryptCipher.init(Cipher.DECRYPT_MODE, keyValue, IVspec);
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);;
    }
  }

  @Override
  public void encrypt(InputStream is, OutputStream os) {
    try {
      byte[] buffer = new byte[BLOCK_SIZE];
      byte[] cipherBlock = new byte[encryptCipher.getOutputSize(buffer.length)];
      int cipherBytes = 0;
      int noBytes = 0;

      while((noBytes = is.read(buffer))!=-1) {
        cipherBytes = encryptCipher.update(buffer, 0, noBytes, cipherBlock);
        os.write(cipherBlock, 0, cipherBytes);
      }

      cipherBytes = encryptCipher.doFinal(cipherBlock, 0);
      os.write(cipherBlock, 0, cipherBytes);
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
  }

  @Override
  public void decrypt(InputStream is, OutputStream os) {
    try {
      byte[] buffer = new byte[BLOCK_SIZE];
      byte[] cipherBlock = new byte[decryptCipher.getOutputSize(buffer.length)];
      int cipherBytes = 0;
      int noBytes = 0;

      while((noBytes = is.read(buffer))!=-1)
      {
        cipherBytes = decryptCipher.update(buffer, 0, noBytes, cipherBlock);
        os.write(cipherBlock, 0, cipherBytes);
      }

      cipherBytes = decryptCipher.doFinal(cipherBlock, 0);
      os.write(cipherBlock, 0, cipherBytes);
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
  }

  // -- Encrypt string and return Hex representation to avoid charset troubles
  public String encrypt(String s) {
    ByteArrayInputStream ba_in;
    ByteArrayOutputStream ba_out = null;

    try {
      ba_in = new ByteArrayInputStream(s.getBytes("UTF-8"));
      ba_out = new ByteArrayOutputStream();
      encrypt(ba_in, ba_out);
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    } finally {
      return Utils.base62encode(ba_out.toByteArray());
    }
  }

  // -- Encrypt Hex representation string
  public String decrypt(String s) {
    ByteArrayInputStream ba_in;
    ByteArrayOutputStream ba_out = null;
    String res = null;

    try {
      ba_in = new ByteArrayInputStream(Utils.base62decode(s));
      ba_out = new ByteArrayOutputStream();
      decrypt(ba_in, ba_out);
      res = ba_out.toString("UTF-8");
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    } finally {
      return res;
    }
  }
}