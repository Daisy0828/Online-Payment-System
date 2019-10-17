package comp3334;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;

/**
 * Created by lizaibeim on 4/12/2018.
 */

public class SHA {
    /**
     * @param args
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String s = "This is for testing, the data content would be digested by SHA1 algorithm";
        String d = sha1(s);
        System.out.print("This is original text [ " + s + " ].\n");
        System.out.print("This is digested test [ " + d + " ].\n");
    }

    public static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < (result.length-4); i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

}
