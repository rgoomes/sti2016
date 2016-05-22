import java.net.*;
import java.io.*;

import java.util.*;
import java.util.concurrent.*;

import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class ChatClientThread extends Thread{
	private Socket           socket   = null;
	private ChatClient       client   = null;
	private DataInputStream  streamIn = null;

	public ChatClientThread(ChatClient _client, Socket _socket){
		client = _client;
		socket = _socket;

		open();
		start();
	}

	public void open(){
		try{
			streamIn = new DataInputStream(socket.getInputStream());
		} catch(IOException ioe) {
			System.out.println("Error getting input stream: " + ioe);
			client.stop();
		}
	}

	public void close(){
		try {
			if(streamIn != null)
				streamIn.close();
		} catch(IOException ioe) {
			System.out.println("Error closing input stream: " + ioe);
		}
	}

	public void run(){
		Boolean readSymKey = false;

		while(true){
			try{
				int bytes = streamIn.readInt();
				byte[] msg = new byte[bytes];
				streamIn.read(msg);

				if(!readSymKey){
					readSymKey = true;
					client.setSymKey(msg);
					client.symMutex.release();
				} else {
					bytes = streamIn.readInt();
					byte[] signature = new byte[bytes];
					streamIn.read(signature);

					client.handle(Util.decrypt(msg, client.getSymKey(), "AES"), signature);
				}

			} catch(IOException ioe) {
				System.out.println("Listening error: " + ioe.getMessage());
				client.stop();
			}
		}
	}
}

public class ChatClient implements Runnable{
	private Socket socket              = null;
	private Thread thread              = null;
	private DataInputStream  console   = null;
	private DataOutputStream streamOut = null;
	private ChatClientThread client    = null;

	private PublicKey publicKey = null;
	private PrivateKey privateKey = null;
	private SecretKey symKey = null;

	public Semaphore symMutex = new Semaphore(1);

	public void setSymKey(byte[] encryptedSecret){
		// decrypt secret key using private key
		symKey = new SecretKeySpec(Util.decrypt(encryptedSecret, privateKey, "RSA/ECB/PKCS1Padding"), "AES");
	}

	public SecretKey getSymKey(){
		return symKey;
	}

	public ChatClient(String serverName, int serverPort){
		System.out.println("Establishing connection to server...");

		try {
			symMutex.acquire();
		} catch (Exception e){
			System.out.println("run() " + e.getMessage());
		}

		// generate client's key pair
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();

			this.publicKey  = kp.getPublic();
			this.privateKey = kp.getPrivate();
		} catch(Exception e){
			System.out.println(e);
		}

		try{
			// Establishes connection with server (name and port)
			socket = new Socket(serverName, serverPort);
			System.out.println("Connected to server: " + socket);
			start();
		} catch(UnknownHostException uhe) {
			// Host unkwnown
			System.out.println("Error establishing connection - host unknown: " + uhe.getMessage());
		} catch(IOException ioexception) {
			// Other error establishing connection
			System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage());
		}
	}

	public void run(){
		// send public key to get symmetric key
		try {
			streamOut.writeInt(publicKey.getEncoded().length);
			streamOut.write(publicKey.getEncoded());
			streamOut.flush();
		} catch(Exception e){
			System.out.println("run() " + e.getMessage());
		}

		// wait for the symmetric to get set
		try {
			symMutex.acquire();
		} catch (Exception e){
			System.out.println("run() " + e.getMessage());
		}

		while (thread != null){
			try{
				// Sends message from console to server
				String tmp = console.readLine();
				byte[] bytes = tmp.getBytes();
				byte[] msg = Util.encrypt(bytes, symKey, "AES");

				if(tmp.length() > 0){
					streamOut.writeInt(msg.length);
					streamOut.write(msg);
					streamOut.flush();

					// send hash for integrity checking
					byte[] encryptedSign = Util.encrypt(Util.hash(bytes), symKey, "AES");
					streamOut.writeInt(encryptedSign.length);
					streamOut.write(encryptedSign);
					streamOut.flush();
				}

			} catch(IOException ioexception) {
				System.out.println("Error sending string to server: " + ioexception.getMessage());
				stop();
			}
		}
	}

	public void handle(byte[] msg, byte[] sign){
		if(!Arrays.equals(Util.hash(msg), Util.decrypt(sign, symKey, "AES"))){
			System.out.println("error: hash not equal");
			return;
		}

		String from_msg = new String(msg);

		// Receives message from server
		if(from_msg.equals(".quit")){
			// Leaving, quit command
			System.out.println("Exiting... Please press RETURN to exit ...");
			stop();
		} else
			// else, writes message received from server to console
			System.out.println(from_msg);
	}

	// Inits new client thread
	public void start() throws IOException {
		console   = new DataInputStream(System.in);
		streamOut = new DataOutputStream(socket.getOutputStream());

		if(thread == null){
			client = new ChatClientThread(this, socket);
			thread = new Thread(this);
			thread.start();
		}
	}

	// Stops client thread
	public void stop(){
		if(thread != null){
			thread.stop();
			thread = null;
		}

		try {
			if(console != null)
				console.close();
			if(streamOut != null)
				streamOut.close();
			if(socket != null)
				socket.close();
		} catch(IOException ioe) {
			System.out.println("Error closing thread...");
		}

		client.close();
		client.stop();
	}

	public static void main(String args[]){
		ChatClient client = null;

		if (args.length != 2)
			// Displays correct usage syntax on stdout
			System.out.println("Usage: java ChatClient host port");
		else
			// Calls new client
			client = new ChatClient(args[0], Integer.parseInt(args[1]));
	}
}
