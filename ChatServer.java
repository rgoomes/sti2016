import java.net.*;
import java.io.*;

import java.util.*;

import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class ChatServerThread extends Thread {
	private ChatServer       server    = null;
	private Socket           socket    = null;
	private DataInputStream  streamIn  = null;
	private DataOutputStream streamOut = null;
	private int              ID        = -1;

	private PublicKey publicKey = null;
	private SecretKey symKey = null;

	public void genSecretKey(){
		// generate client's session key
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			symKey = keyGen.generateKey();
		} catch(Exception e){
			System.out.println("ChatServerThread/genSecretKey() " + e.getMessage());
		}
	}

	public SecretKey getSecretKey(){
		return symKey;
	}

	public void setPublicKey(byte[] bytes){
		try {
			this.publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
		} catch(Exception e){
			System.out.println("ChatServerThread/setPublicKey() " + e.getMessage());
		}

		this.genSecretKey();
	}

	public PublicKey getPublicKey(){
		return publicKey;
	}

	public ChatServerThread(ChatServer _server, Socket _socket){
		super();
		server = _server;
		socket = _socket;
		ID     = socket.getPort();
	}

	// Sends message to client
	public void send(byte[] msg, int type){
		try {
			streamOut.writeInt(type);
			streamOut.writeInt(msg.length);
			streamOut.write(msg);
			streamOut.flush();
		} catch(IOException ioexception) {
			System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
			server.remove(ID);
			stop();
		}
	}

	// Gets id for client
	public int getID(){
		return ID;
	}

	// Runs thread
	public void run(){
		System.out.println("Server Thread " + ID + " running.");
		Boolean readPublicKey = false;

		while(true){
			try {
				int type = streamIn.readInt();
				int bytes = streamIn.readInt();
				byte[] msg = new byte[bytes];
				streamIn.read(msg);

				if(type == Util.PUBLIC){
					readPublicKey = true;
					this.setPublicKey(msg);
					server.handle(ID, new byte[0], new byte[0], true);
				} else if(readPublicKey){
					// read also hash to compare signatures
					type = streamIn.readInt();
					bytes = streamIn.readInt();
					byte[] signature = new byte[bytes];
					streamIn.read(signature);

					server.handle(ID, msg, signature, false);
				}

			} catch(IOException ioe) {
				System.out.println(ID + " ERROR reading: " + ioe.getMessage());
				server.remove(ID);
				stop();
			}
		}
	}

	// Opens thread
	public void open() throws IOException {
		streamIn = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		streamOut = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
	}

	// Closes thread
	public void close() throws IOException {
		if(socket != null)
			socket.close();
		if(streamIn != null)
			streamIn.close();
		if(streamOut != null)
			streamOut.close();
	}
}

public class ChatServer implements Runnable {
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private Thread thread = null;
	private int clientCount = 0;

	public ChatServer(int port){
		try {
			// Binds to port and starts server
			System.out.println("Binding to port " + port);
			server_socket = new ServerSocket(port);
			System.out.println("Server started: " + server_socket);
			start();
		} catch(IOException ioexception) {
			// Error binding to port
			System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
		}
	}

	public void run(){
		while(thread != null) {
			try {
				// Adds new thread for new client
				System.out.println("Waiting for a client ...");
				addThread(server_socket.accept());
			} catch(IOException ioexception) {
				System.out.println("Accept error: " + ioexception); stop();
			}
		}
	}

	public void start(){
		if(thread == null){
			// Starts new thread for client
			thread = new Thread(this);
			thread.start();
		}
	}

	public void stop(){
		if(thread != null){
			// Stops running thread for client
			thread.stop();
			thread = null;
		}
	}

	private int findClient(int ID){
		// Returns client from id
		for(int i = 0; i < clientCount; i++)
			if(clients[i].getID() == ID)
				return i;

		return -1;
	}

	public synchronized void handle(int ID, byte[] input, byte[] sign, Boolean isHandshake){
		int client = findClient(ID);
		PublicKey pk = clients[client].getPublicKey();
		SecretKey sk = clients[client].getSecretKey();
		String msg = new String(Util.decrypt(input, sk, "AES"));

		if(isHandshake == true){
			// send secret key encrypted with client's public key to the client
			clients[client].send(Util.encrypt(sk.getEncoded(), pk, "RSA/ECB/PKCS1Padding"), Util.PUBLIC);
		} else {

			if(!Arrays.equals(Util.decrypt(sign, sk, "AES"), Util.hash(Util.decrypt(input, sk, "AES")))){
				System.out.println("error: hash not equal");
				return;
			}

			if(msg.equals(".quit")){
				// Client exits
				byte[] quit_msg = ".quit".getBytes();
				clients[client].send(Util.encrypt(quit_msg, sk, "AES"), Util.NORMAL);
				clients[client].send(Util.encrypt(Util.hash(quit_msg), sk, "AES"), Util.NORMAL);

				// Notify remaing users
				byte[] exit_msg = ("Client " + ID + " exits..").getBytes();

				for(int i = 0; i < clientCount; i++){
					if(i != client){
						clients[i].send(Util.encrypt(exit_msg, clients[i].getSecretKey(), "AES"), Util.NORMAL);
						clients[i].send(Util.encrypt(Util.hash(exit_msg), clients[i].getSecretKey(), "AES"), Util.NORMAL);
					}
				}

				remove(ID);
			} else {
				// Brodcast message for every client online
				byte[] new_msg = (ID + ": " + msg).getBytes();

				for(int i = 0; i < clientCount; i++){
					clients[i].send(Util.encrypt(new_msg, clients[i].getSecretKey(), "AES"), Util.NORMAL);
					clients[i].send(Util.encrypt(Util.hash(new_msg), clients[i].getSecretKey(), "AES"), Util.NORMAL);
				}
			}
		}
	}

	public synchronized void remove(int ID){
		int pos = findClient(ID);

		if(pos >= 0){
			// Removes thread for exiting client
			ChatServerThread toTerminate = clients[pos];
			System.out.println("Removing client thread " + ID + " at " + pos);
			if(pos < clientCount-1)
				for(int i = pos+1; i < clientCount; i++)
					clients[i-1] = clients[i];

			clientCount--;

			try{
				toTerminate.close();
			} catch(IOException ioe) {
				System.out.println("Error closing thread: " + ioe);
			}

			toTerminate.stop();
		}
	}

	private void addThread(Socket socket){
		if(clientCount < clients.length){
			// Adds thread for new accepted client
			System.out.println("Client accepted: " + socket);
			clients[clientCount] = new ChatServerThread(this, socket);

			try {
				clients[clientCount].open();
				clients[clientCount].start();
				clientCount++;
			} catch(IOException ioe){
				System.out.println("Error opening thread: " + ioe);
			}
		} else
			System.out.println("Client refused: maximum " + clients.length + " reached.");
	}


	public static void main(String args[]){
		ChatServer server = null;

		if(args.length != 1)
			// Displays correct usage for server
			System.out.println("Usage: java ChatServer port");
		else
			// Calls new server
			server = new ChatServer(Integer.parseInt(args[0]));
	}
}
