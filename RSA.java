package comp3334;
import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


/**
 * Created by lizaibeim on 4/12/2018.
 */

public class RSA {

    public static final String CHARSET = "GBK";
    public static final String RSA_ALGORITHM = "RSA";


    public static void main (String[] args) throws Exception {
        Map<String, String> keyMap = RSA.createKeys(1024);
        String  publicKey = keyMap.get("publicKey");
        String  privateKey = keyMap.get("privateKey");
        System.out.println("Public key: \n\r" + publicKey);
        System.out.println("Private key: \n\r" + privateKey);

        System.out.println("Public key to encrypt, Private key to decrypt");
        String str = "Today is Sunday\n" +
                "It is a sunny day\n" +
                "It is suitable for hiking\n" +
                "But I am doing the project for COMP3334\n" +
                "I hope for graduating from university as soon as possible\n" +
                "COMP3334 is interesting and useful.\n";
        System.out.println("\rPlaintext: \r\n" + str);
        System.out.println("\rThe size of Plaintext: \r\n" + str.getBytes().length);
        String encodedData = RSA.publicEncrypt(str, RSA.getPublicKey(publicKey));
        System.out.println("Ciphertext: \r\n" + encodedData);
        String decodedData = RSA.privateDecrypt(encodedData, RSA.getPrivateKey(privateKey));
        System.out.println("Plaintext: \r\n" + decodedData);


    }

    public static Map<String, String> createKeys(int keySize){
        //Create a KeyPairGenerator object for the RSA algorithm
        KeyPairGenerator kpg;
        try{
            kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        }catch(NoSuchAlgorithmException e){
            throw new IllegalArgumentException("No such algorithm-->[" + RSA_ALGORITHM + "]");
        }

        //RSA algorithm requires a trusted random number source
        SecureRandom secureRandom = new SecureRandom();
        //Initialize the KeyPairGenerator object, key length
        kpg.initialize(keySize, secureRandom);
        //Generate the key pair
        KeyPair keyPair = kpg.generateKeyPair();
        //Get the public key
        Key publicKey = keyPair.getPublic();
        String publicKeyStr = Base64.getUrlEncoder().encodeToString(publicKey.getEncoded());
        //Get the private key
        Key privateKey = keyPair.getPrivate();
        String privateKeyStr = Base64.getUrlEncoder().encodeToString(privateKey.getEncoded());
        Map<String, String> keyPairMap = new HashMap<String, String>();
        keyPairMap.put("publicKey", publicKeyStr);
        keyPairMap.put("privateKey", privateKeyStr);

        return keyPairMap;
    }

    /**
     * Get Public Key
     * @param publicKey Key string (base64 encoded)
     * @throws Exception
     */
    public static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Get the public key object through the X509 encoded Key instruction)
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.getUrlDecoder().decode(publicKey));
        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
        return key;
    }

    /**
     * Get Private Key
     * @param privateKey Key string (base64 encoded)
     * @throws Exception
     */
    public static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Get the private key object through the PKCS #8 encoded Key instruction)
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.getUrlDecoder().decode(privateKey));
        RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        return key;
    }

    /**
     * Public key encryption
     * @param data
     * @param publicKey
     * @return
     */
    public static String publicEncrypt(String data, RSAPublicKey publicKey){
        try{
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.getUrlEncoder().encodeToString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET), publicKey.getModulus().bitLength()));
        }catch(Exception e){
            throw new RuntimeException("Encrypt String [" + data + "] encounter an exception", e);
        }
    }

    /**
     * Private key decryption
     * @param data
     * @param privateKey
     * @return
     */

    public static String privateDecrypt(String data, RSAPrivateKey privateKey){
        try{
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.getUrlDecoder().decode(data), privateKey.getModulus().bitLength()), CHARSET);
        }catch(Exception e){
            throw new RuntimeException("Decrypt String [" + data + "] encounter an exception", e);
        }
    }

    /**
     * Private key encryption
     * @param data
     * @param privateKey
     * @return
     */

    public static String privateEncrypt(String data, RSAPrivateKey privateKey){
        try{
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return Base64.getUrlEncoder().encodeToString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET), privateKey.getModulus().bitLength()));
        }catch(Exception e){
            throw new RuntimeException("Encrpyt string [" + data + "] encounter an exception", e);
        }
    }

    /**
     * Public key decryption
     * @param data
     * @param publicKey
     * @return
     */

    public static String publicDecrypt(String data, RSAPublicKey publicKey){
        try{
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.getUrlDecoder().decode(data), publicKey.getModulus().bitLength()), CHARSET);
        }catch(Exception e){
            throw new RuntimeException("Decrypt string [" + data + "] encounter an exception", e);
        }
    }

    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize){
        int maxBlock = 0;
        if(opmode == Cipher.DECRYPT_MODE){
            maxBlock = keySize / 8;
        }else{
            maxBlock = keySize / 8 - 11;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] buff;
        int i = 0;
        try{
            while(datas.length > offSet){
                if(datas.length-offSet > maxBlock){
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                }else{
                    buff = cipher.doFinal(datas, offSet, datas.length-offSet);
                }
                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
        }catch(Exception e){
            throw new RuntimeException("The encryption for data with threshold ["+maxBlock+"] is abnormal", e);
        }
        byte[] resultDatas = out.toByteArray();

        try {
            out.close();
        } catch(IOException e) {
        }
        return resultDatas;
    }

}