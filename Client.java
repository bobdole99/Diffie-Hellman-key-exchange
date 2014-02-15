/*Michael Gugala
10020767
Assignment 3 CPSC 418
University of Calgary
Client.java
*/

import java.io.*;
import java.net.*;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.math.BigInteger;
import java.util.Random;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


public class Client 
{
	private Socket sock;  			//Socket to communicate with.
	private DataOutputStream out;	//outstream for sock
	private DataInputStream in;		//instream for sock
	
	private byte[] aesKey;			// shared AES key for all encryption
	
	private boolean debug;	//print debug messages?
	
	/**
	 * Main method, starts the client.
	 * @param args args[0] needs to be a hostname, args[1] a port number.
	 */
	public static void main (String [] args)
	{
		boolean setDebug = false;
		
		if (args.length < 2)
		{
			System.out.println ("Usage: java Client hostname port# <debug>");
			System.out.println ("hostname is a string identifying your server");
			System.out.println ("port is a positive integer identifying the port to connect to the server");
			return;
		}
		if (args.length == 3)
		{
			if(args[2].compareTo("debug") == 0)
			{
				setDebug = true;
			}
		}

		try {
			Client cl = new Client (args[0], Integer.parseInt(args[1]), setDebug);
		}
		catch (NumberFormatException e) {
			System.out.println ("Usage: java Client hostname port#");
			System.out.println ("Second argument was not a port number");
			return;
		}
	}
	
	/**
	 * Constructor, in this case does everything.
	 * @param ipaddress The hostname to connect to.
	 * @param port The port to connect to.
	 */
	public Client (String ipaddress, int port, boolean setDebug)
	{
		debug = setDebug;
		
		/* Allows us to get input from the keyboard. */
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		
		/* Try to connect to the specified host on the specified port. */
		try {
			sock = new Socket (InetAddress.getByName(ipaddress), port);
		}
		catch (UnknownHostException e) {
			System.out.println ("Usage: java Client hostname port#");
			System.out.println ("First argument is not a valid hostname");
			return;
		}
		catch (IOException e) {
			System.out.println ("Could not connect to " + ipaddress + ".");
			return;
		}
		
		/* Status info */
		System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);
		
		try {
			in = new DataInputStream(sock.getInputStream());
			out = new DataOutputStream(sock.getOutputStream());
		}
		catch (UnknownHostException e) {
			System.out.println ("Unknown host error.");
			return;
		}
		catch (IOException e) {
			System.out.println ("Could not create output stream.");
			return;
		}
		
		//get shared AES key for encrypting file
		aesKey = key_agreement();
		debug(new String(aesKey));
		
		send_file();
		
		System.out.println ("Client exiting.");
		
		try {
	    	out.close();
	    	in.close();
			sock.close();
			stdIn.close();
		} catch (IOException e) {
			return;
		}	
	}
	
	//Diffie-Hellman key agreement protocol
	//Based on implementation in JCE docs
	public byte[] key_agreement()
	{
		debug("Starting key agreement");
		
		try {
			/*
			***	Generate the parameters for diffie-hellman
			*/
			//Get the 1024 bit prime number p
			byte[] encodedp = receive();
			
			//Decode encodedp into a BigInteger p
			BASE64Decoder mybase64decoder = new BASE64Decoder( );

			byte[] pbytes = mybase64decoder.decodeBuffer( new String(encodedp)  );
			BigInteger p= new BigInteger(pbytes);

			debug("Client Received p:"+p);

			//Get the primitive element
			byte[] encodedg = receive();

			//Decode encodedg into a BigInteger g
			
  			byte[] gbytes = mybase64decoder.decodeBuffer( new String(encodedg)  );
			BigInteger g= new BigInteger(gbytes);

			debug("Client Received g:"+g);
			

			//Generate the private data (random a)
			boolean gooda=false;
			BigInteger one= BigInteger.valueOf( (long) 1);
			BigInteger pminusone= p.subtract( one);	
			SecureRandom myrand = SecureRandom.getInstance("SHA1PRNG");
		
 			BigInteger a=null;
			while( !gooda ){ 
				a = new BigInteger(1025,myrand);
				if (a.compareTo(pminusone) < 0){
					gooda= true;
				}	
			}

			
			//Compute the public key (g^a) (using your own fast exponentiation)
			BigInteger ya= Utilities.fastmodexp( g ,a,p);
			
			
			//Encode the public key in base 64 
			BASE64Encoder mybase64encoder = new BASE64Encoder();
			String ya64string = mybase64encoder.encodeBuffer(  ya.toByteArray() );
			

			
			debug("Receiving servers public key, yb");
			//get servers public key
			byte[] ybstringbytes = receive();



			//send the encoded clients public key
			debug("Sending public key, ya,  to Server");
			send( ya64string);


			//Decode the server public key
			// g^b = decoded(ybstringbytes)
			byte[] ybbytes = mybase64decoder.decodeBuffer( new String(ybstringbytes)  );
			BigInteger yb= new BigInteger(ybbytes);
			
			//Get shared key
			debug("Derive the DH key in Client");
			// key = (g^b)^a
			BigInteger key= Utilities.fastmodexp(yb,a,p); 

			//Apply a hash function to the key
			byte[] secretKey = Utilities.keyhash(key.toByteArray() );


			
			debug("Finished key agreement");
			return secretKey;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public void send_file()
	{
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		
		String infilename;
		String outfilename; 
		
		FileInputStream infile;
		byte[] message;
		byte[] messagehash;
		byte[] ciphertext;
		
		try {
			debug("Starting File Transfer");
			System.out.println("Please enter the source filename:");
			infilename = stdIn.readLine();
			infile = new FileInputStream(infilename);
			
			System.out.println("Please enter the destination filename:");
			outfilename = stdIn.readLine();
			
			//Send the output file name
			send(Utilities.encrypt(outfilename.getBytes(), aesKey));
			
			//Send the filesize
			send(Utilities.encrypt(String.valueOf(infile.available()).getBytes(), aesKey));	
			
			//Load file into byte array
			message = new byte[infile.available()];
			infile.read(message);
			
			//append the hash/mac for data integrity
			messagehash = Utilities.append_hash(message, aesKey);
			
			//Encrypt the message/mac
			ciphertext = Utilities.encrypt(messagehash, aesKey);
			
			debug("Sending ciphertext");
			
			//Send the encrypted file
			send(ciphertext);
			
			debug("ciphertext sent");
			
			debug("get verification status");
			String verified = new String(receive());
			
			if(verified.compareTo("Passed") == 0)
			{
				System.out.println("File verification passed.");
			}
			else
			{
				System.out.println("File verification failed.");
			}
			
			infile.close();
			
		} catch (Exception e) {
			System.out.println ("Could not read source file");
			return;
		}
		
	}
	
	public int send(String message)
	{
		return Utilities.send(message.getBytes(), out);
	}
	
	public int send(byte[] message)
	{
		return Utilities.send(message, out);
	}
	
	public byte[] receive() throws IOException
	{
		return Utilities.receive(in);
	}	
	
	private void debug(String s)
	{
		if(debug) System.out.println("Debug: " + s);
	}
	
}
