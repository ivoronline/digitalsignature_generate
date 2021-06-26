import java.io.*;
import java.security.*;
import java.security.spec.*;

class ValidateSignature {

  public static void main(String[] args) throws FileNotFoundException {

    try {

      //GET SIGNATURE FROM FILE
      FileInputStream    signatureFile     = new FileInputStream("src/main/resources/Signature.txt");
      byte[]             signatureToVerify = new byte[signatureFile.available()];
                         signatureFile.read(signatureToVerify);
                         signatureFile.close();

      //GET PUBLIC KEY FROM FILE
      FileInputStream    publicKeyFile = new FileInputStream("src/main/resources/PublicKey.txt");
      byte[]             encodedKey    = new byte[publicKeyFile.available()];
                         publicKeyFile.read(encodedKey);
                         publicKeyFile.close();

      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedKey);
      KeyFactory         keyFactory = KeyFactory.getInstance("DSA", "SUN");
      PublicKey          publicKey  = keyFactory.generatePublic(pubKeySpec);

      //GET DATA FROM FILE
      FileInputStream     dataFile   = new FileInputStream("src/main/resources/Data.txt");
      BufferedInputStream dataBuffer = new BufferedInputStream(dataFile);

      //GENERATE NEW SIGNATURE (FROM PUBLIC KEY AND DATA)
      Signature           signature = Signature.getInstance("SHA1withDSA", "SUN");
                          signature.initVerify(publicKey);
      byte[]              buffer    = new byte[1024];
      while (dataBuffer.available() != 0) {
        int len = dataBuffer.read(buffer);
        signature.update(buffer, 0, len);
      };
      dataBuffer.close();

      //COMPARE SIGNATURES
      boolean verifies = signature.verify(signatureToVerify);
      System.out.println("Signature is valid: " + verifies);

    }
    catch (Exception e) {
      System.err.println("Caught exception " + e.toString());
    }

  }

}