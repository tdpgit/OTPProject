import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class Client {
    public static void main(String[] args) {
        int portno = 3000;
        byte[] otpkey = {(byte)0xAA,(byte)0xAA, (byte)0xAA, (byte)0xAA};
        String hostaddress = "localhost";
        String message = "This is my default message";

        //try to set values through args
        try {
            portno = Integer.parseInt(args[0]);
            otpkey = DatatypeConverter.parseHexBinary(args[1]);
            hostaddress = args[2];
            message = args[3];
            for(int i = 4; i < args.length; i++) {
                message = message + " " + args[i];
            }
        } catch (Exception e) {
            //use defaults
        }

        //try connecting to server
        try {
            //get ipaddress
            InetAddress address = InetAddress.getByName(hostaddress);

            //create socket
            Socket socket = new Socket(address, portno);

            //encode message
            final byte[] decodedMessage = message.getBytes();
            final byte[] encoded = new byte[decodedMessage.length];
            final byte[] key = new byte[decodedMessage.length];
            new SecureRandom(otpkey).nextBytes(key);
            for(int i = 0; i < decodedMessage.length; i++) {
                encoded[i] = (byte)(decodedMessage[i] ^ key[i]);
            }

            //get length of encoded
            int encodedLength = encoded.length;

            //add length to message to send
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(ByteBuffer.allocate(4).putInt(encodedLength).array());
            baos.write(encoded);
            byte[] sendMessage = baos.toByteArray();

            //send message to server
            OutputStream os = socket.getOutputStream();
            os.write(sendMessage, 0, sendMessage.length);
            System.out.println("Send message: " + message);
//            //wait for confirmation
//            boolean waiting = true;
//            InputStream is = socket.getInputStream();
//            byte[] fromServer = new byte[18];
//            ByteArrayOutputStream serverMessage = new ByteArrayOutputStream();
//            int readSize;
//            while((readSize = is.read(fromServer, 0, fromServer.length)) > 0) {
//                serverMessage.write(fromServer, 0, readSize);
//                if((new String(serverMessage.toByteArray()) == "I got the message.") || readSize == -1) {
//                    waiting = false;
//                }
//            }

//            System.out.println("Server: " + new String(serverMessage.toByteArray()));
            System.out.println("Ending Connection.");
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
