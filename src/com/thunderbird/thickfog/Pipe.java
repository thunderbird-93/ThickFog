package com.thunderbird.thickfog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Pipe {
  final private static Logger LOGGER = LoggerFactory.getLogger(Pipe.class);
  final public static long CHUNK_SIZE = 4194304;     // 4MB chunk size
  private Crypto_AES_CBC lightCipher;
  private Crypto_Serpent_AES_CBC heavyChipher;
  private String originalFile;                       // Original file path & name
  private String encryptedPath;                      // Folder where file Manifest and Chunks are stored
  private FileManifest manifest;

/*  - private FileManifest
  - private HashingDigest
  - reconcile()
  - push()
  - pull()
  - private readManifest
  - private writeManifest*/

  public Pipe(String originalFile, String encryptedPath, byte[] key0, byte[] key1, byte[] IV) {
    this.originalFile = originalFile;
    this.encryptedPath = encryptedPath;

    // -- create manifest instance and generate initialization vectors
    manifest = new FileManifest();
    manifest.setIV0(Utils.getSecureRandom(Crypto.BLOCK_SIZE));
    manifest.setIV1(Utils.getSecureRandom(Crypto.BLOCK_SIZE));

    lightCipher = new Crypto_AES_CBC(key0, IV);
    heavyChipher = new Crypto_Serpent_AES_CBC(key0, manifest.getIV0(), key1, manifest.getIV1());
  }

  public void push() {

  }

  public String getOriginalFile() {
    return originalFile;
  }

  public void setOriginalFile(String originalFile) {
    this.originalFile = originalFile;
  }

  public String getEncryptedPath() {
    return encryptedPath;
  }

  public void setEncryptedPath(String encryptedPath) {
    this.encryptedPath = encryptedPath;
  }
}
