/*Michael Gugala
10020767
Assignment 3 CPSC 418
University of Calgary
Server.java
*/
import java.io.IOException;
import java.net.*;
import java.util.Vector;


public class Server
{
	private ServerSocket serversock;
	private Vector <ServerThread> serverthreads;  //holds the active threads
	private boolean shutdown;  //allows clients to shutdown the server
	private int clientcounter;  //id numbers for the clients
	
	boolean debug = false;	//print debug messages?

	/**
	 * Main method
	 * @param args First argument should be the port to listen on.
	 */
	public static void main (String [] args)
	{
		boolean setDebug = false;
		
		if (args.length < 1)
		{
			System.out.println ("Usage: java Server port#");
			return;
		}
		if (args.length == 2)
		{
			if(args[1].compareTo("debug") == 0)
			{
				setDebug = true;
			}
		}

		try {
			Server serv = new Server (Integer.parseInt(args[0]), setDebug);
		}
		catch (ArrayIndexOutOfBoundsException e) {
			System.out.println ("Usage: java Server port#");
			System.out.println ("Second argument is not a port number.");
			return;
		}
		catch (NumberFormatException e) {
			System.out.println ("Usage: java Server port#");
			System.out.println ("Second argument is not a port number.");
			return;
		}
	}
	
	/**
	 * Constructor, makes a new server listening on specified port.
	 * @param port The port to listen on.
	 */
	public Server (int port, boolean setDebug)
	{
		debug = setDebug; 
		
		clientcounter = 0;
		shutdown = false;
		try {
			serversock = new ServerSocket (port);
		}
		catch (IOException e) {
			System.out.println ("Could not create server socket.");
			return;
		}
		/* Server socket open, make a vector to store active threads. */
		serverthreads = new Vector <ServerThread> (0,1);
		
		/* listen on the socket for connections. */
		listen ();
	}
	
	/**
	 * Allows threads to check and see if the server is shutting down.
	 * @return True if the server has been told to shutdown.
	 */
	public boolean getFlag ()
	{
		return shutdown;
	}
	
	/**
	 * Called by a thread who's client has asked to exit.  Gets rid of the thread.
	 * @param st The ServerThread to remove from the vector of active connections.
	 */
	public void kill (ServerThread st)
	{
		System.out.println ("Killing Client " + st.getID() + ".");
		
		/* Find the thread in the vector and remove it. */
		for (int i = 0; i < serverthreads.size(); i++)
		{
			if (serverthreads.elementAt(i) == st)
				serverthreads.remove(i);
		}
	}
	
	/**
	 * Called by a thread who's client has instructed the server to shutdown.
	 */
	public void killall ()
	{
		shutdown = true;
		System.out.println ("Shutting Down Server.");
		
		/* For each active thread, close it's socket.  This will cause the thread
		 * to stop blocking because of the IO operation, and check the shutdown flag.
		 * The thread will then exit itself when it sees shutdown is true.  Then exits. */
		for (int i = serverthreads.size() - 1; i >= 0; i--)
		{
			try {
				System.out.println ("Killing Client " + serverthreads.elementAt(i).getID() + ".");
				serverthreads.elementAt(i).getSocket().close();
			}
			catch (IOException e)
			{System.out.println ("Could not close socket.");}
			serverthreads.remove(i);
		}
		try {
			serversock.close();
		} 
		catch (IOException e) {
			System.out.println ("Could not close server socket.");
		}		
	}
	
	/**
	 * Waits for incoming connections and spins off threads to deal with them.
	 */
	private void listen ()
	{
		Socket client = new Socket ();
		ServerThread st;
		
		/* Should only do this when it hasn't been told to shutdown. */
		while (!shutdown)
		{
			/* Try to accept an incoming connection. */
			try {
				client = serversock.accept ();
				/* Spew some info about the client */
				System.out.println ("Client on machine " + client.getInetAddress().getHostAddress() + " has connected on port " + client.getLocalPort() + ".");
				
				/* Create a new thread to deal with the client, add it to the vector of open connections.
				 * Finally, start the thread's execution. Start method makes the threads go by calling their
				 * run() methods. */
				st = new ServerThread (client, this, clientcounter++);
				serverthreads.add (st);
				st.start ();
			}
			catch (IOException e) {
				/* Server Socket is closed, probably because a client told the server to shutdown */
			}
		}
	}
}
