package com.thunderbird.thickfog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;

public class Pipe {
  final private static Logger LOGGER = LoggerFactory.getLogger(Pipe.class);
  final public static long CHUNK_SIZE = 4194304;     // 4MB chunk size
  final static String MANIFEST_EXT = ".manifest";
  final static String CHUNK_EXT = ".part";

  private Crypto_AES_CBC lightCipher;
  private Crypto_Serpent_AES_CBC heavyChipher;
  private File originalFile;                         // Original file path & name
  private File encryptedPath;                        // Folder where file Manifest and Chunks are stored
  private FileManifest manifest;

/*  - private FileManifest
  - private HashingDigest
  - update()
  - push()
  - pull()
  - private readManifest
  - private writeManifest*/

  public Pipe(String originalFile, String encryptedPath, byte[] key0, byte[] key1, byte[] IV) {
    this.originalFile = new File(originalFile);
    this.encryptedPath = new File(encryptedPath);

    // -- create manifest instance and generate initialization vectors
    manifest = new FileManifest();
    manifest.setIV0(Utils.getSecureRandom(Crypto.BLOCK_SIZE));
    manifest.setIV1(Utils.getSecureRandom(Crypto.BLOCK_SIZE));
    manifest.setName(this.originalFile.getName());

    lightCipher = new Crypto_AES_CBC(key0, IV);
    heavyChipher = new Crypto_Serpent_AES_CBC(key0, manifest.getIV0(), key1, manifest.getIV1());
  }

  // -- Split original file into chunks, encrypt them and create manifest file
  public void push() {
    BufferedInputStream bis = null;

    try {
      bis = new BufferedInputStream(new FileInputStream(originalFile));
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Opening: " + originalFile);
        LOGGER.debug("Size: " + originalFile.length() / (1024 * 1024) + "MB");
      }


    }
    catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
    finally {
      if (bis != null) {
        try {
          bis.close();
        }
        catch (Exception e) {
          if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
        }
      }
    }

  }

  public File getOriginalFile() {
    return originalFile;
  }

  public void setOriginalFile(File originalFile) {
    this.originalFile = originalFile;
  }

  public File getEncryptedPath() {
    return encryptedPath;
  }

  public void setEncryptedPath(File encryptedPath) {
    this.encryptedPath = encryptedPath;
  }
}
