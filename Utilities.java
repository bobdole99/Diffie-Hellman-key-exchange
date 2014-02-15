/*Michael Gugala
10020767
Assignment 3 CPSC 418
University of Calgary
Utilities.java
*/
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.util.Arrays;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;


public class Utilities {

	/** 
	*Method that hashes a Diffie-Hellman key into a usable 128 bit AES key
	*used with Client.java and Server.java
	*@param byte[] key (Diffie Hellman key)
	*@returns byte[]  (128 bit AES key)
	**/ 
	public static byte[] keyhash(byte[] key){
		
		String digestalg= "MD5";
		byte[] computeddigest=null;

		try{
			MessageDigest mydigest= MessageDigest.getInstance(digestalg);
			mydigest.update(key);
			computeddigest=mydigest.digest();

		} catch (NoSuchAlgorithmException  nsae){
			System.out.println("Could not use specified Message Digest algorithm\n"+nsae);
			System.exit(0);
		}
		
		return computeddigest;
	}


	public static byte[] append_hash(byte[] message, byte[] key)
	{
		byte[] ret = null;
		
		try {
			//Init the Mac with our aes key
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(keySpec);
			
			//Get our mac
			byte[] m = mac.doFinal(message);
			
			//Append the mac to the message
			ret = new byte[message.length+m.length];
			System.arraycopy(message, 0, ret, 0, message.length);
			System.arraycopy(m, 0, ret, message.length, m.length);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return ret;
	}
	
	public static boolean verify_hash(byte[] messageHash, byte[] key)
	{
		boolean ret = false;
		
		try {
			//Split the array into the message and the hash
			byte[] message = new byte[messageHash.length-20];
			byte[] hash = new byte[20];
			
			System.arraycopy(messageHash, 0, message, 0, message.length);
			System.arraycopy(messageHash, message.length, hash, 0, hash.length);
			
			//Init the Mac with our aes key
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(keySpec);
			
			//Get the mac of the message
			byte[] m = mac.doFinal(message);
			
			//compare the the mac sent and the one calculated
			ret = Arrays.equals(m, hash);
			
		} catch (Exception e) {
			//If there is an error, we know that hash can't be correct
			ret = false;
		}
		
		return ret;
	}
	
	public static byte[] encrypt(byte[] message, byte[] key)
	{
		byte[] ret = null;
		
		try {
			//Init the cipher with our key
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			
			//encrypt the message
			byte[] cipherText = cipher.doFinal(message);
			byte[] params = cipher.getParameters().getEncoded();
			
			//Combine the cipherText and message into one byte array
			ret = new byte[cipherText.length+18];
			System.arraycopy(cipherText, 0, ret, 0, cipherText.length); 
			System.arraycopy(params, 0, ret, cipherText.length, params.length);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return ret;
	}
	
	public static byte[] decrypt(byte[] decrypt, byte[] key)
	{
		byte[] message = null;
		
		try {
			//Split the array into the ciphertext and its params
			byte[] cipherText = new byte[decrypt.length-18];
			byte[] paramsEnc = new byte[18];
			
			System.arraycopy(decrypt, 0, cipherText, 0, cipherText.length);
			System.arraycopy(decrypt, cipherText.length, paramsEnc, 0, paramsEnc.length);
			
			//Init the parameters
			AlgorithmParameters params = AlgorithmParameters.getInstance("AES");
	        		params.init(paramsEnc);
	        
	      		 //Init the cipher for decryption
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
			
			//decrypt the cipherText
			message = cipher.doFinal(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return message;
	}
	
	public static int send(byte[] message, DataOutputStream out)
	{

		try {
			out.writeInt(message.length);	//Send length of message
			out.write(message);				//Send the message bytes
			
			out.flush();	//flush the stream
		    
		    if ((new String(message).compareTo("exit") == 0) || (new String(message).compareTo("die") == 0))
		    {
		    	return 1;
		    }
		} catch (IOException e) {
			System.out.println ("Could not read from input.");
			return 1; 
		}	
	    
	    return 0;
	    
	}
	
	public static byte[] receive(DataInputStream in) throws IOException
	{
		byte[] message = null;

		int size = in.readInt();	//read the message size
		
		message = new byte[size];
		int i = 0;
		int total = 0;
		do
		{
			i = in.read(message, total, size-total);	//read the bytes into the array
			total += i;
		} while (total != size); //read until we have read size bits

		return message;
	}


	/** 
	*calculates g^q mod p using fast exponentiation algorithm
	*@param BigInteger g
	*@param BigInteger q
	*@param BigInteger p
	*@returns BigInteger (result of g^q mod p)
	**/ 
	public static BigInteger fastmodexp(BigInteger g, BigInteger q, BigInteger p){
		BigInteger r = g.remainder(p);

		int k=q.bitLength()-1;		

		for( int i=k-1; i >= 0; i--){

			if( q.testBit(i) ){
				r= r.multiply(r); // r(m+1)=r(m)^2
				r= r.multiply(g); //r(m+1)=r(m)^2*g
				r= r.remainder(p);				
			}else{
				r= r.multiply(r); // r(m+1)=r(m)^2
				r= r.remainder(p);
			}
		} 
		return r;
	}
}
