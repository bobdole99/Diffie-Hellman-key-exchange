/*Michael Gugala
10020767
Assignment 3 CPSC 418
University of Calgary
ServerThread.java, 

Implemented the run() method

*/
import java.io.*;
import java.net.*;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

import java.math.BigInteger;
import java.util.Random;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
/*Michael Gugala
10020767
Assignment 3 CPSC 418
University of Calgary
ServerThread.java
*/

/**
 * Thread to deal with clients who connect to Server.  Put what you want the
 * thread to do in it's run() method.
 * @author Karel P. Bergmann
 */
/**
 * Added Key agreement and encryption stuff
 * @author Mohsen Alimomeni
 */

public class ServerThread extends Thread
{
	private Socket sock;  		//The socket it communicates with the client on.
	private DataOutputStream out;	//Out stream to the client
	private DataInputStream in;		//instream for sock
	
	private byte[] aesKey;		// shared AES key for all encryption
	
	private Server parent;			//Reference to Server object for message passing.
	private int idnum; 				//The client's id number.
	
	/**
	 * Constructor, does the usual stuff.
	 * @param s Communication Socket.
	 * @param p Reference to parent thread.
	 * @param id ID Number.
	 */
	public ServerThread (Socket s, Server p, int id)
	{
		parent = p;
		sock = s;
		idnum = id;
	}
	
	/**
	 * Getter for id number.
	 * @return ID Number
	 */
	public int getID ()
	{
		return idnum;
	}
	
	/**
	 * Getter for the socket, this way the parent thread can
	 * access the socket and close it, causing the thread to
	 * stop blocking on IO operations and see that the server's
	 * shutdown flag is true and terminate.
	 * @return The Socket.
	 */
	public Socket getSocket ()
	{
		return sock;
	}
	
	/**
	 * This is what the thread does as it executes.  Listens on the socket
	 * for incoming data and then echos it to the screen.  A client can also
	 * ask to be disconnected with "exit" or to shutdown the server with "die".
	 */
	public void run ()
	{		
		try {
			in = new DataInputStream(sock.getInputStream());
			out = new DataOutputStream(sock.getOutputStream());
		}
		catch (UnknownHostException e) {
			System.out.println ("Unknown host error.");
			return;
		}
		catch (IOException e) {
			System.out.println ("Could not establish communication.");
			return;
		}
		
		//Generate a key to use to encrypt files
		aesKey = key_agreement();
		debug(new String(aesKey));
		
		//Get a file from the client
		get_file();
		
		parent.kill (this);
		try {
			out.close();
			in.close ();
			sock.close ();
		}
		catch (IOException e)
		{
			return;
		}
	}
	
	public byte[] key_agreement()
	{
		debug("Starting key agreement in Server");
		
		try{
			//Generate the prime number p=2q+1 using 1024 bit q
			boolean pprime= false;
			int certainty= 100;
			BigInteger p=null;
			BigInteger q=null;

			BigInteger one= BigInteger.valueOf( (long) 1);

			SecureRandom myrand = SecureRandom.getInstance("SHA1PRNG");

			debug("Finding safe prime (this may take several minutes)");
			while( !(pprime) ){
			
				//q is a prime with certainty 1-1/2^100
				q= BigInteger.probablePrime(1024,myrand);

				p= q.shiftLeft(1);	//p=2q
				p= p.setBit(0);	//p=2q+1

				pprime= p.isProbablePrime(certainty);		
				
			}

			debug("Server calculated q:"+ q );
			debug("Server calculated p:"+ p );


			//Encode and Send p to the client
			BASE64Encoder mybase64encoder = new BASE64Encoder();

			String bigpstring = mybase64encoder.encodeBuffer(  p.toByteArray() );
			send( bigpstring);
			debug("Sending p to Client");

			//Generate a primitive element as described in the assignment file.
			//Implement it in a function and call it here

			int g= findPrimitive(p,q);
			BigInteger bigg= BigInteger.valueOf( (long) g);
			debug("Server calculated g:"+g);
			
			//Encode and Send g to the client
			//to be encoded in base 64
			
			String biggstring = mybase64encoder.encodeBuffer(  bigg.toByteArray() );
			send(biggstring);
			debug("Sending g to Client");

			//Generate the private data (random b)
			boolean goodb= false;
			BigInteger pminusone= p.subtract( one);			
 			BigInteger b=null;
			while( !goodb ){ 
				b = new BigInteger(1025,myrand);
				if (b.compareTo(pminusone) < 0){
					goodb= true;
				}	
			}

			//Compute the public key (g^b) (using your own fast exponentiation)

			BigInteger yb= Utilities.fastmodexp( BigInteger.valueOf((long) g) ,b,p);

			//Encode the public key in base 64 
     			
  			String yb64string = mybase64encoder.encodeBuffer(  yb.toByteArray() );
			
			//send the encoded clients public key
			debug("Sending public key, yb ,  to Client");
			send(yb64string);
			
			debug("Receiving Client's public key, ya");
			//get client public key
			byte[] yastringbytes = receive();


			//Decode the client public key
			// g^a = decoded(yastringbytes)
  			BASE64Decoder mybase64decoder = new BASE64Decoder( );
  			byte[] yabytes = mybase64decoder.decodeBuffer( new String(yastringbytes)  );
			BigInteger ya= new BigInteger(yabytes);
			
			//Get shared key
			debug("Derive the DH key in Server");
			// key = (g^a)^b
			BigInteger key= Utilities.fastmodexp(ya,b,p); 

			//Apply a hash function to the key
			byte[] secretKey = Utilities.keyhash(key.toByteArray() );

			debug("Done key agreement");
			return secretKey;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public void get_file()
	{
		FileOutputStream outfile;
		String filename;
		byte[] message;
		byte[] ciphertext;
		
		try {
			debug("Begin getting file");
			
			//Get the filename to write to
			debug("r: filename");
			filename = new String(Utilities.decrypt(receive(), aesKey));
			System.out.println("Receiving " + filename);
			
			//get file size
			byte[] fsize = receive();
			
			outfile = new FileOutputStream(filename);
			
			//Get the encrypted, integrity-protected file
			debug("r: message");
			ciphertext = receive();			
			
			debug("Decrypting message");
			
			//decrypt message
			message = Utilities.decrypt(ciphertext, aesKey);
			
			if(Utilities.verify_hash(message, aesKey))
			{
				debug("Signature verification passed");
				send("Passed");
				
				//Write all but the hash to the file
				outfile.write(message, 0, message.length-20);
			}
			else
			{
				debug("Signature verification failed");
				send("Failed");
			}
			
			outfile.close();
			
			debug("done getting file");
		} catch (Exception e) {
			return;
		}
	}
	
	public int send(String message){
		return Utilities.send(message.getBytes(), out);
	}
	
	public int send(byte[] message){
		return Utilities.send(message, out);
	}
	
	public byte[] receive() throws IOException{
		return Utilities.receive(in);
	}
	
	private void debug(String s){
		if(parent.debug) System.out.println("Debug: " + s);
	}

	/** 
	*Method that finds a primitive root of p
	* uses property that p=2q+1 where q is prime thus factors of phi(p)=p-1  are q and 2
	*@param BigInteger p
	* @param  BigInteger q
	*@returns int g (primitive root of p)
	**/ 

	private static int findPrimitive(BigInteger p, BigInteger q){
		int g=1;
		boolean foundprimitive= false;
		
		BigInteger one= BigInteger.valueOf( (long) 1);

		while( ! (foundprimitive) ) {

			g++;

			//check g^2 first, so we don't need to use fast modular exponentiation unless it passes
			
			BigInteger bigg= BigInteger.valueOf( (long) g );
			BigInteger biggsq= bigg.multiply(bigg);
			BigInteger gsqmodp = bigg.remainder(p);
			
			if ( one.compareTo(gsqmodp) != 0 ){
				//g^2 mod p is not 1 so check g^q

				BigInteger biggtoqmodp = Utilities.fastmodexp(bigg,q,p);

				if ( one.compareTo( biggtoqmodp) != 0){

					foundprimitive = true;
				}				
			}
		}
		return g;
	}
}
