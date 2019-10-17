package comp3334;
import java.io.BufferedReader;  
import java.io.FileInputStream;  
import java.io.InputStreamReader;  
import java.io.PrintWriter;  
import java.net.Socket;  
import java.security.KeyStore;  
import javax.net.SocketFactory;  
import javax.net.ssl.KeyManagerFactory;  
import javax.net.ssl.SSLContext;  
import javax.net.ssl.SSLSocketFactory;
import java.util.Map;
import java.util.Scanner;

public class SSLClient {  
    private static String CLIENT_KEY_STORE = "/Library/Java/JavaVirtualMachines/jdk1.8.0_101.jdk/Contents/Home/bin/client_ks";
    private static String CLIENT_KEY_STORE_PASSWORD = "456456";
    private static String publicKey_server;
    private static String publicKey_client;
    private static String privateKey_client;
    private static SHA sha;
    private static RSA rsa;

      
    public static void main(String[] args) throws Exception {
        sha = new SHA();
        rsa = new RSA();
        Map<String, String> keyMap = RSA.createKeys(512);
        publicKey_client = keyMap.get("publicKey");
        privateKey_client = keyMap.get("privateKey");

        System.out.println("Public key for client: \n\r" + publicKey_client);
        System.out.println("Private key for client: \n\r" + privateKey_client);


        // Set the key store to use for validating the server cert.  
        System.setProperty("javax.net.ssl.trustStore", CLIENT_KEY_STORE);  
        //System.setProperty("javax.net.debug", "ssl,handshake");
        SSLClient client = new SSLClient();  
        Socket s = client.clientWithCert();  

        PrintWriter writer = new PrintWriter(s.getOutputStream());  
        BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream()));
        //get server's public key, assume it as secure
        publicKey_server = reader.readLine();
        System.out.print("publicKey_server "+publicKey_server+"\n");

        //transfer the public Key of client to server, assume it as secure
        writer.println(publicKey_client);
        writer.flush();

        //Get the first message from server, and check its integrity
        while (true) {
            //Get the first message from server, which is the transcation amount
            String cipher_aount = reader.readLine();
            System.out.println("Ciphertext: [ " + cipher_aount + " ]\n");
            String[] a = Datadecrypt(cipher_aount);
            if(a[1].equals("true")){
                //the data integrity is guaranteed
                System.out.println("The content is secure:" + a[0] + "\n");
                writer.println(Dataencrypt("true",sha));
                writer.flush();
                break;
            }else {
                //the data has been changed
                System.out.println("The content is not secure.\n");
                //ask for retransferring from server
                writer.println(Dataencrypt("false",sha));
                writer.flush();
            }
        }


        Scanner scan = new Scanner(System.in);
    	System.out.print("Input transaction password?");
    	String str1;
    	str1 = scan.next();
        System.out.println("The transaction password is : " + str1);
        scan.close();
        
        writer.println(Dataencrypt(str1,sha));
        writer.flush();

        //wait for the first response from server, whether the password is transferred correctly or not
        while(true) {
            String response = reader.readLine();
            String[] plaintext = Datadecrypt(response);
            if(plaintext[1].equals("true") && plaintext[0].substring(4).equals("true")){
                System.out.println("The content is transferred correctly");
                break;
            } else { //retransfer the password agian
                writer.println(Dataencrypt(str1,sha));
                writer.flush();
            }
        }
        s.close(); 
    }

    //get the decrypted message and check its integrity
    private static String[] Datadecrypt(String ciphertext) throws Exception{
        //decrypt the message first by RSA, then do hash for content to check data integrity
        String digested = RSA.privateDecrypt(ciphertext,RSA.getPrivateKey(privateKey_client));
        System.out.println("Digested: [ " + digested + " ]\n");

        //split the digested
        String hash = digested.substring(5,37);
        String content = digested.substring(45);
        System.out.println("hash:" + hash + "content:" + content);
        String checkout = sha.sha1(content);

        if (checkout.equals(hash)) {
            String [] a = {content,"true"};
            return a;
        } else {
            String [] a = {content,"false"};
            return a;
        }
    }

    private static String Dataencrypt(String data, SHA sha) throws Exception{
        //cancatenate teh data with seconds
        java.sql.Timestamp time= new java.sql.Timestamp(System.currentTimeMillis());
        int seconds = StrToMinute(time.toString().substring(14,19));
        System.out.println("Curren time: " + time + " " + seconds + "\n");
        String s = String.format("%04d",seconds);
        data = s+data;

        //digest the data with sha1 algorithm
        String hash = sha.sha1(data);
        String digested = "Hash:" + hash + "Content:" + data;
        //encrypt the digested data packet via RSA algorithmn with publicKey_client
        System.out.println("The data after hash is : [ " + digested + " ]\n");
        String ciphertext = RSA.publicEncrypt(digested,RSA.getPublicKey(publicKey_server));
        System.out.println("The digested data after encryption is : [ " + ciphertext + " ]\n");

        return ciphertext;
    }

    //convert the time xx:xx to int to indicate seconds
    public static int StrToMinute(String str) {
        String[] strs = str.split(":");
        if(strs.length != 2) {
            System.out.println("unvalid input");
            return -1;
        }
        int minute = Integer.valueOf(strs[0]);
        int second = Integer.valueOf(strs[1]);
        return (minute * 60 + second);
    }

    private Socket clientWithoutCert() throws Exception {  
        SocketFactory sf = SSLSocketFactory.getDefault();  
        Socket s = sf.createSocket("localhost", 8443);
        return s;  
    }  
  
    private Socket clientWithCert() throws Exception {  
        SSLContext context = SSLContext.getInstance("TLS");  
        KeyStore ks = KeyStore.getInstance("jceks");  
          
        ks.load(new FileInputStream(CLIENT_KEY_STORE), null);  
        KeyManagerFactory kf = KeyManagerFactory.getInstance("SunX509");  
        kf.init(ks, CLIENT_KEY_STORE_PASSWORD.toCharArray());  
        context.init(kf.getKeyManagers(), null, null);  
          
        SocketFactory factory = context.getSocketFactory();  
        Socket s = factory.createSocket("localhost", 8443);
        return s;  
    }  
}