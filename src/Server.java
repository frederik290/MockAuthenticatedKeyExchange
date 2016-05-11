import javafx.util.Pair;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 * Created by frederik290 on 11/05/16.
 */
public class Server {

    public static void main(String[] args) {
        Server server = new Server();
        server.init();
    }

    public void init(){
        IPSec ipSec = new IPSec();
        BigInteger e = new BigInteger("3");
        KeyObject privateKey = ipSec.generatePrivateKey(e);
        KeyObject publicKey = new KeyObject(e,privateKey.getN());

        BigInteger randomNumber =  ipSec.getRandomNumber(); //used for exponent
        BigInteger messageToSend = ipSec.computeNumberToSend(randomNumber);

        ServerSocket serverSocket = registerOnPort(40103);

        if(serverSocket != null){
            System.out.println("Server successfully started...  ");
        }else{
            System.out.println("Something went wrong");
            return;
        }

        Socket clientSocket = waitForConnectionFromClient(serverSocket);
        System.out.println("Server established connection with client...");

        try {
            //constructe the streams
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());

            //received a pair
            Pair<BigInteger,KeyObject> receivedPair = (Pair<BigInteger,KeyObject>) objectInputStream.readObject();
            BigInteger receivedMessage = receivedPair.getKey();
            KeyObject receivedPublicKey = receivedPair.getValue();

            // computed the common key
            BigInteger commonKey = ipSec.computeCommonKey(receivedMessage,randomNumber);

            //sends a pair of message and public key
            Pair<BigInteger,KeyObject> pair = new Pair<>(messageToSend, publicKey);
            objectOutputStream.writeObject(pair);

            //receives the servers signed message
            BigInteger receivedSignedMessage = (BigInteger) objectInputStream.readObject();
            System.out.println("Server received signed message from client... ");

            //signs the sent message with our private key
            BigInteger signedMessage = ipSec.sign(privateKey,messageToSend);

            //sends the signed message
            objectOutputStream.writeObject(signedMessage);

            // Tries to verify the servers identity
            if(ipSec.verify(receivedPublicKey,receivedMessage,receivedSignedMessage)){
                System.out.println("The server has verified the clients identity...");
                System.out.println("The common key is: " + commonKey);
            }else{
                System.out.println("The server could not verify the clients identity...");
            }

        } catch (IOException | ClassNotFoundException ex){
            ex.printStackTrace();
        }

    }

    private ServerSocket registerOnPort(int portNumber) {
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(portNumber);
        } catch (IOException e) {
            System.err.println("Cannot open server socket on port number" + portNumber);
            System.err.println(e);
            System.exit(-1);
        }
        return serverSocket;
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

    private Socket waitForConnectionFromClient(ServerSocket serverSocket) {
        Socket res = null;
        try {
            res = serverSocket.accept();
        } catch (IOException e) {
            // We return null on IOExceptions
        }
        return res;
    }
}
