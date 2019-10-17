package comp3334;
import java.io.BufferedReader;  
import java.io.FileInputStream;
import java.io.InputStreamReader;  
import java.io.PrintWriter;  
import java.net.ServerSocket;  
import java.net.Socket;  
import java.security.KeyStore;
import javax.net.ServerSocketFactory;  
import javax.net.ssl.KeyManagerFactory;  
import javax.net.ssl.SSLContext;  
import javax.net.ssl.SSLServerSocket;
import java.util.Map;
import java.util.Scanner;

public class SSLServer extends Thread {
    private static SHA sha;
    private static RSA rsa;
    private Socket socket;
    private static String publicKey_server; //the server's public key, will be transfer to client
    private static String privateKey_server; //the server's private key, keep by server and decrypt message sent from client
    private static String publicKey_client; //the client's public key, used to encrypt message sent to client

  
    public SSLServer(Socket socket) {
        //initialize server for each socket session to generate server public key and private key for RSA alogrithm
        this.sha = new SHA();
        this.rsa = new RSA();
        this.socket = socket;
        Map<String, String> keyMap = RSA.createKeys(1024);
        publicKey_server = keyMap.get("publicKey");
        privateKey_server = keyMap.get("privateKey");

    }
  
    public void run() {  
        try {
            System.out.println("Public key for server: \n\r" + publicKey_server);
            System.out.println("Private key for server: \n\r" + privateKey_server);

            PrintWriter writer = new PrintWriter(socket.getOutputStream());
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            //send server's public key to client, assume it as secure
            writer.println(publicKey_server);
            writer.flush();

            //get client's public key, assume it as secure
            publicKey_client = reader.readLine();
            System.out.print("publicKey_client: "+publicKey_client+"\n");

        	Scanner scan = new Scanner(System.in);
        	System.out.print("Set transaction amount: ");
        	String content;
        	content = scan.next();
            scan.close();

            //set the first request to client (Transcation amount verify)
            writer.println(Dataencrypt(content, sha));
            writer.flush();

            //Waif for the first response from client, whether the amount is sent correctly or not
            while(true) {
                String response = reader.readLine();
                String[] plaintext = Datadecrypt(response);
                if(plaintext[1].equals("true") && plaintext[0].substring(4).equals("true")){
                    System.out.println("The content is transferred correctly");
                    break;
                } else { //retransfer the data agian
                    writer.println(Dataencrypt(content,sha));
                    writer.flush();
                }
            }


            //Get the first message sent from client and check its integrity
            while (true) {
                //Read the first message from client, which is the password
                String password = reader.readLine();
                System.out.println("Ciphertext: [ " + password + " ]\n");
                String[] a = Datadecrypt(password);
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
            writer.close();  
            socket.close();  
        } catch (Exception e) {
  
        }  
    }  
  
    private static String SERVER_KEY_STORE = "/Library/Java/JavaVirtualMachines/jdk1.8.0_101.jdk/Contents/Home/bin/server_ks";
    private static String SERVER_KEY_STORE_PASSWORD = "123123";

    //get the decrypted message and check its integrity
    private static String[] Datadecrypt(String ciphertext) throws Exception{
        //decrypt the message first by RSA, then do hash for content to check data integrity
        String digested = RSA.privateDecrypt(ciphertext,RSA.getPrivateKey(privateKey_server));
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
        String ciphertext = RSA.publicEncrypt(digested,RSA.getPublicKey(publicKey_client));
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



    public static void main(String[] args) throws Exception {  
        System.setProperty("javax.net.ssl.trustStore", SERVER_KEY_STORE);
        //System.setProperty("javax.net.debug", "ssl,handshake");
        SSLContext context = SSLContext.getInstance("TLS");  
          
        KeyStore ks = KeyStore.getInstance("jceks");  
        ks.load(new FileInputStream(SERVER_KEY_STORE), null);  
        KeyManagerFactory kf = KeyManagerFactory.getInstance("SunX509");  
        kf.init(ks, SERVER_KEY_STORE_PASSWORD.toCharArray());  
          
        context.init(kf.getKeyManagers(), null, null);  
  
        ServerSocketFactory factory = context.getServerSocketFactory();  
        ServerSocket _socket = factory.createServerSocket(8443);
        ((SSLServerSocket) _socket).setNeedClientAuth(true);  
  
        while (true) {  
            new SSLServer(_socket.accept()).start();  
        }  
    }  
}  
