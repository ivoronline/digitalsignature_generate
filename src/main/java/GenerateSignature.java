import java.io.*;
import java.security.*;

class GenerateSignature {

  public static void main(String[] args) {

    try {

      //GENERATE KEY PAIR
      SecureRandom        random     = SecureRandom.getInstance("SHA1PRNG", "SUN");
      KeyPairGenerator    keyGen     = KeyPairGenerator.getInstance("DSA", "SUN");
                          keyGen.initialize(1024, random);
      KeyPair             keyPair    = keyGen.generateKeyPair();
      PrivateKey          privateKey = keyPair.getPrivate();
      PublicKey           publicKey  = keyPair.getPublic();

      //GET DATA FROM FILE
      FileInputStream     dataFile   = new FileInputStream("src/main/resources/Data.txt");
      BufferedInputStream dataBuffer = new BufferedInputStream(dataFile);

      //CREATE SIGNATURE (FROM PRIVATE KEY AND DATA)
      Signature           signature = Signature.getInstance("SHA1withDSA", "SUN");
                          signature.initSign(privateKey);
      byte[]              buffer    = new byte[1024];
      while (dataBuffer.available() != 0) {
        int len = dataBuffer.read(buffer);
        signature.update(buffer, 0, len);
      };
      dataBuffer.close();

      //GENERATE DIGITAL SIGNATURE OF THE DATA
      byte[]            digitalSignature = signature.sign();

      //SAVE SIGNATURE TO FILE
      FileOutputStream  signatureFile = new FileOutputStream("src/main/resources/Signature.txt");
                        signatureFile.write(digitalSignature);
                        signatureFile.close();

      //SAVE PUBLIC KEY TO FILE
      byte[]            publicKeyBytes = publicKey.getEncoded();
      FileOutputStream  publicKeyFile  = new FileOutputStream("src/main/resources/PublicKey.txt");
                        publicKeyFile.write(publicKeyBytes);
                        publicKeyFile.close();

    } catch (Exception e) {
      System.err.println("Caught exception " + e.toString());
    }

  }

}