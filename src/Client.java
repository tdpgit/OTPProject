
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import java.security.*;

class ClientArguments {
    @Option(name = "-p", usage = "port")
    public int port;
    @Option(name = "-t", usage = "host name")
    String hostName;
    @Option(name = "-P", usage = "passphrase")
    String passphrase;
}

public class Client {
    public static void main(String[] args) throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        if (args.length < 3) {
            System.out.println("Missing arguments.\nNeed -p (port number) -t (hostname) -P (\"passphrase\")");
        }

        //try to get info from args
        ClientArguments clientArguments = new ClientArguments();
        CmdLineParser cmdLineParser = new CmdLineParser(clientArguments);
        try {
            cmdLineParser.parseArgument(args);
        } catch (Exception e) {
            System.out.println("Failed to read arguments.\n" +
                    "Need -p (port number) -t (hostname) -P (\"passphrase\")\"");
        }


        new ClientThread(clientArguments.hostName, clientArguments.port,
                clientArguments.passphrase).start();

    }
}
