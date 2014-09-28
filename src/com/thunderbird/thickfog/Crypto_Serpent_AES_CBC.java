package com.thunderbird.thickfog;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;

// -- CBC encryption class, use for files content
public class Crypto_Serpent_AES_CBC extends Crypto {
  byte[] key0 = null;                    // Serpent key
  byte[] IV0 = null;                     // Serpent initialization vector needed by the CBC mode

  Cipher encryptCipher0 = null;
  Cipher decryptCipher0 = null;

  public Crypto_Serpent_AES_CBC(byte[] pass, byte[] iv, byte[] pass0, byte[] iv0) {
    super(pass, iv);

    // get the key0 and the IV0 for Serpent
    key0 = new byte[pass0.length];
    System.arraycopy(pass0, 0, key0, 0, pass0.length);
    IV0 = new byte[BLOCK_SIZE];
    System.arraycopy(iv0, 0, IV0, 0, iv0.length);
  }

  @Override
  public void resetCiphers() {
    super.resetCiphers();
    encryptCipher0 = null;
    decryptCipher0 = null;
  }

  @Override
  public void initCiphers() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    // -- Init Encryptors
    // 0. Serpent
    encryptCipher0 = Cipher.getInstance("Serpent/CBC/PKCS7Padding", "BC");
    SecretKey keyValue0 = new SecretKeySpec(key0, "Serpent");
    AlgorithmParameterSpec IVspec0 = new IvParameterSpec(IV0);
    encryptCipher0.init(Cipher.ENCRYPT_MODE, keyValue0, IVspec0);
    // 1. AES
    encryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
    SecretKey keyValue = new SecretKeySpec(key, "AES");
    AlgorithmParameterSpec IVspec = new IvParameterSpec(IV);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keyValue, IVspec);

    // -- Init Decryptors
    // 0. Serpent
    decryptCipher0 = Cipher.getInstance("Serpent/CBC/PKCS7Padding", "BC");
    decryptCipher0.init(Cipher.DECRYPT_MODE, keyValue0, IVspec0);
    // 1. AES
    decryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
    decryptCipher.init(Cipher.DECRYPT_MODE, keyValue, IVspec);
  }

  @Override
  public void encrypt(InputStream is, OutputStream os) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] buffer = new byte[BLOCK_SIZE];
    int noBytes = 0;
    byte[] cipherBlock = new byte[encryptCipher0.getOutputSize(buffer.length)];       // Serpent and AES should have same block size
    int cipherBytes;
    ByteArrayInputStream ba_in;
    ByteArrayOutputStream ba_out;

    // -- Apply Serpent and store result in temp stream
    ba_out = new ByteArrayOutputStream();
    while((noBytes = is.read(buffer))!=-1)
    {
      cipherBytes = encryptCipher0.update(buffer, 0, noBytes, cipherBlock);
      ba_out.write(cipherBlock, 0, cipherBytes);
    }
    cipherBytes = encryptCipher0.doFinal(cipherBlock, 0);
    ba_out.write(cipherBlock, 0, cipherBytes);

    // -- Apply AES
    ba_in = new ByteArrayInputStream(ba_out.toByteArray());
    while((noBytes = ba_in.read(buffer))!=-1)
    {
      cipherBytes = encryptCipher.update(buffer, 0, noBytes, cipherBlock);
      os.write(cipherBlock, 0, cipherBytes);
    }
    cipherBytes = encryptCipher.doFinal(cipherBlock, 0);
    os.write(cipherBlock, 0, cipherBytes);
  }

  @Override
  public void decrypt(InputStream is, OutputStream os) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] buffer = new byte[BLOCK_SIZE];
    int noBytes = 0;
    byte[] cipherBlock = new byte[decryptCipher0.getOutputSize(buffer.length)];   // Serpent and AES should have same block size
    int cipherBytes;
    ByteArrayInputStream ba_in;
    ByteArrayOutputStream ba_out;

    // -- Decrypt AES and store result in temp stream
    ba_out = new ByteArrayOutputStream();
    while((noBytes = is.read(buffer))!=-1)
    {
      cipherBytes = decryptCipher.update(buffer, 0, noBytes, cipherBlock);
      ba_out.write(cipherBlock, 0, cipherBytes);
    }
    cipherBytes = decryptCipher.doFinal(cipherBlock, 0);
    ba_out.write(cipherBlock, 0, cipherBytes);

    // -- Decrypt Serpent
    ba_in = new ByteArrayInputStream(ba_out.toByteArray());
    while((noBytes = ba_in.read(buffer))!=-1)
    {
      cipherBytes = decryptCipher0.update(buffer, 0, noBytes, cipherBlock);
      os.write(cipherBlock, 0, cipherBytes);
    }
    cipherBytes = decryptCipher0.doFinal(cipherBlock, 0);
    os.write(cipherBlock, 0, cipherBytes);
  }
}