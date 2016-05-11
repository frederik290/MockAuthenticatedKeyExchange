import javafx.util.Pair;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * Created by Jeppe Vinberg on 12-04-2016.
 */
public class RSA {

    private BigInteger one = BigInteger.ONE;
    private BigInteger cachedQ = null, cachedP = null;

    private MessageDigest sha_256;

    public RSA(){
        try{
            sha_256 = MessageDigest.getInstance("SHA-256");
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public KeyObject generatePrivateKey(int k, BigInteger e){
        Random r = new Random();
        BigInteger p, q, n;
        int k1 = k/2;
        int k2 = (int) Math.ceil(k/2);
        while(true){
            p = getP(k1, e, r);
            q = getQ(k2, e, r);
            if(p != null && q != null){
                if(p.equals(q)){
                    cachedQ = null;
                    continue;
                }
                n = p.multiply(q);
                break;
            }

        }
        BigInteger qMinusOne = q.subtract(one);
        BigInteger pMinusOne = p.subtract(one);
        return new KeyObject(e.modInverse(qMinusOne.multiply(pMinusOne)), n);
    }

    private BigInteger getQ(int k, BigInteger e, Random r){
        if(cachedQ != null){
            return cachedQ;
        }
        BigInteger q = BigInteger.probablePrime(k, r);
        BigInteger qMinusOne = q.subtract(one);
        if(e.gcd(qMinusOne).equals(one)){
            cachedQ = q;
        }
        return cachedQ;

    }

    private BigInteger getP(int k, BigInteger e, Random r){
        if(cachedP != null){
            return cachedP;
        }
        BigInteger p = BigInteger.probablePrime(k, r);
        BigInteger pMinusOne = p.subtract(one);
        if(e.gcd(pMinusOne).equals(one)){
            cachedP = p;
        }
        return cachedP;
    }

    public BigInteger encrypt(KeyObject key, BigInteger message){
        return encryptDecrypt(key.getKey(), key.getN(), message);
    }

    public BigInteger decrypt(KeyObject key, BigInteger message){
        return encryptDecrypt(key.getKey(), key.getN(), message);
    }

    private BigInteger encryptDecrypt(BigInteger key, BigInteger n, BigInteger message){
        return message.modPow(key, n);
    }

    public BigInteger sign(KeyObject privateKey, BigInteger message){
        BigInteger hash = generateHash(message);
        BigInteger signature = encrypt(privateKey, hash);
        return signature;
    }

    public boolean verify(KeyObject publicKey, BigInteger message, BigInteger signature){
        BigInteger hash = generateHash(message);
        return decrypt(publicKey, signature).equals(hash);
    }

    public BigInteger signWithoutHash(KeyObject privateKey, BigInteger message){
        BigInteger signature = encrypt(privateKey, message);
        return signature;
    }

    private BigInteger generateHash(BigInteger message){
        sha_256.update(message.toByteArray());
        byte[] h = sha_256.digest();
        return new BigInteger(1,h);

    }
}
