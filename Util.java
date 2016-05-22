import javax.crypto.*;
import java.security.*;

class Util {

	public static byte[] encrypt(byte[] msg, Key key, String algorithm){
		try {
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(msg);
		} catch (Exception e){
			System.out.println("encrypt() " + e.getMessage());
		}

		return null;
	}

	public static byte[] decrypt(byte[] msg, Key key, String algorithm){
		try {
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(msg);
		} catch (Exception e){
			System.out.println("decrypt() " + e.getMessage());
		}

		return null;
	}

	public static byte[] hash(byte[] msg) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			return md.digest(msg);
		} catch (Exception e) {
			System.out.println("hash() " + e.getMessage());
		}

		return null;
	}

	// for print purposes
	public static String byteArrayToHexString(byte[] b) {
		String result = "";

		for(int i = 0; i < b.length; i++)
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);

		return result;
	}

	public static int modulo16(int bytes){
		return bytes + 16 - bytes % 16;
	}
}
