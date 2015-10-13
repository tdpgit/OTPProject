import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class Server {

    public static void main(String[] args) {

        boolean serverRunning = true;
        int portno = 3000;
        byte[] otpkey = {(byte)0xAA,(byte)0xAA, (byte)0xAA, (byte)0xAA};
        //try to set port and otp
        try {
            portno = Integer.parseInt(args[0]);
            otpkey = DatatypeConverter.parseHexBinary(args[1]);
        } catch(Exception e) {
           //use defaults
        }

        try {
            //create socket
            ServerSocket server = new ServerSocket(portno);


            //listen while server runs
            while(serverRunning) {
                //accept clients and start thread
                Socket socket = server.accept();
                new ProxyThread(socket, otpkey).start();
            }

        } catch(Exception e) {
            e.printStackTrace();
        }

    }
}

class ProxyThread extends Thread {
    private Socket socket;
    private byte[] otpkey;
    public ProxyThread(Socket socket, byte[] otpkey) {
        this.socket = socket;
        this.otpkey = otpkey;
    }

    public void run() {
        try {
            System.out.println("Client Connected.");
            //get input
            InputStream is = socket.getInputStream();
            int readSize;

            //find length of message
            byte[] messageLength = new byte[4];
            ByteArrayOutputStream messageLengthHolder = new ByteArrayOutputStream();
            while((readSize = is.read(messageLength, 0, messageLength.length)) > 0) {
                messageLengthHolder.write(messageLength, 0, readSize);

                if(messageLengthHolder.toByteArray().length == 4) {
                    break;
                }
            }
//            is.read(messageLength, 0, messageLength.length);
            int holdLength = ByteBuffer.wrap(messageLengthHolder.toByteArray()).getInt();
            System.out.println("Message Length: " + holdLength);

            //find rest of message
            byte[] encodedMessage = new byte[holdLength];
            ByteArrayOutputStream encodedMessageHolder = new ByteArrayOutputStream();
            while((readSize = is.read(encodedMessage, 0, holdLength)) > 0) {
                encodedMessageHolder.write(encodedMessage, 0, readSize);

                if(encodedMessageHolder.toByteArray().length == holdLength) {
                    break;
                } else if(encodedMessageHolder.toByteArray().length == holdLength) {
                    //length of message is longer than expected
                    System.out.println("To many characters closing socket.");
                    socket.close();
                    return;
                }
            }
//            is.read(encodedMessage, 0, holdLength);
            encodedMessage = encodedMessageHolder.toByteArray();
            System.out.println("The encoded string: " + new String(encodedMessage));

            //decode message
            final byte[] decoded = new byte[encodedMessage.length];
            final byte[] key = new byte[encodedMessage.length];
            new SecureRandom(otpkey).nextBytes(key);
            for(int i = 0; i < encodedMessage.length; i++) {
                decoded[i] = (byte)(encodedMessage[i] ^ key[i]);
            }
            System.out.println("The decoded message: " + new String(decoded));

            //confirm the message was recieved
            OutputStream os = socket.getOutputStream();
            String returnMessage = "I got the message.";
            os.write(returnMessage.getBytes(), 0, returnMessage.getBytes().length);

            //close socket
            System.out.println("Close Socket.");

            //important info to print
            System.out.println("Important: ");
            System.out.println("client IP address: " + socket.getRemoteSocketAddress());
            System.out.println("ciphertext: " + DatatypeConverter.printHexBinary(encodedMessageHolder.toByteArray()));
            System.out.println("Plaintext: " + new String(decoded));

            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
