import javafx.util.Pair;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Base64;


public class Client {
    public static void main(String[] args) {
        Client client = new Client();
        client.init();
    }

    public void init(){
        IPSec ipSec = new IPSec();
        BigInteger e = new BigInteger("7");
        KeyObject privateKey = ipSec.generatePrivateKey(e);
        KeyObject publicKey = new KeyObject(e,privateKey.getN());

        BigInteger randomNumber =  ipSec.getRandomNumber(); //used for exponent
        BigInteger messageToSend = ipSec.computeNumberToSend(randomNumber);

        Socket socket = connectToServer(getLocalHostAddress(), "40103");
        if(socket == null) {
            System.out.println("Something went wrong");
            return;
        }
        System.out.println("The client has established a connection to the server");
        try {
            //constructe the streams
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

            //sends a pair of message and public key
            Pair<BigInteger,KeyObject> pair = new Pair<>(messageToSend, publicKey);
            objectOutputStream.writeObject(pair);

            //received a pair
            Pair<BigInteger,KeyObject> receivedPair = (Pair<BigInteger,KeyObject>) objectInputStream.readObject();
            BigInteger receivedMessage = receivedPair.getKey();
            KeyObject receivedPublicKey = receivedPair.getValue();

            // computed the common key
            BigInteger commonKey = ipSec.computeCommonKey(receivedMessage,randomNumber);

            //signs the sent message with our private key
            BigInteger signedMessage = ipSec.sign(privateKey,messageToSend);

            //sends the signed message
            objectOutputStream.writeObject(signedMessage);

            //receives the servers signed message
            BigInteger receivedSignedMessage = (BigInteger) objectInputStream.readObject();
            System.out.println("Client received the servers signed message...");

            // Tries to verify the servers identity
            if(ipSec.verify(receivedPublicKey,receivedMessage,receivedSignedMessage)){
                System.out.println("The client has verified the servers identity...");
                System.out.println("The common key is: " + commonKey);
            }else{
                System.out.println("The client could not verify the servers identity...");
            }

        } catch (IOException | ClassNotFoundException ex){ex.printStackTrace();}

    }

    private Socket connectToServer(String serverAddress, String portNumber) {
        Socket socket = null;
        try {
            socket = new Socket(serverAddress, Integer.parseInt(portNumber));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return socket;
    }

    private String getLocalHostAddress() {
        String address = null;
        try {
            InetAddress localHost = InetAddress.getLocalHost();
            address = localHost.getHostAddress();
        } catch (UnknownHostException e) {
            System.err.println("Cannot resolve Internet address of the local host");
            System.err.println(e);
            System.exit(-1);
        }
        return address;
    }
}
