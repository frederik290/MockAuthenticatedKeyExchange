import java.io.Serializable;
import java.math.BigInteger;

/**
 * Created by frederik290 on 11/05/16.
 */
public class KeyObject implements Serializable {
    private BigInteger key;
    private BigInteger n;

    public KeyObject(BigInteger key, BigInteger n){
        this.key = key;
        this.n = n;
    }

    public BigInteger getKey(){
        return key;
    }

    public BigInteger getN(){
        return n;
    }

    public String toString(){
        return "key: " + key + ", " + "n: " + n;
    }
}
