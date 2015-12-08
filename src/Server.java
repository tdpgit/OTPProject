
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import sun.tools.jar.CommandLine;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;

class ServerArguments {
    @Option(name = "-p", usage = "port number")
    public int port;
    @Option(name = "-P", usage = "passphrase")
    public String passphrase;
}

public class Server {

    public static void main(String[] args) {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        boolean serverRunning = true;

        if (args.length < 2) {
            System.out.println("Missing arguments.\nNeed -p (port number) -P (\"passphrase\")" +
                    "\nMake sure passphrase is in quotations");
            return;
        }

        //get command line arguments from switches
        ServerArguments serverArguments = new ServerArguments();
        CmdLineParser cmdLineParser = new CmdLineParser(serverArguments);

        try {
            cmdLineParser.parseArgument(args);
        } catch (Exception e) {
            System.out.println("Failed to read arguments.\n" +
                    "Need -p (port number) -P (\"passphrase\"\\nMake sure passphrase is in quotations\"");
            return;
        }

        try {
            //create socket
            ServerSocket server = new ServerSocket(serverArguments.port);
            
            System.out.println("Waiting for clients.");

            //listen while server runs
            while(serverRunning) {
                //accept clients and start thread
                Socket socket = server.accept();
                new ServerThread(socket, serverArguments.passphrase).start();
            }

        } catch(Exception e) {
            e.printStackTrace();
        }

    }
}

