import java.math.BigInteger;
import java.util.Random;

/**
 * Created by frederik290 on 11/05/16.
 */
public class IPSec {
    private static final String stringForp = "751474279403938544240249605991757804416635024979862468954659370757544943253351" +
            "6775221564552407296844608742071460521528886991203761037337422295830214855409152507207785689674001681103594" +
            "2023428715412518122053121174699512385159293805239348312888357014150880093879839799455017982828491114580661" +
            "2006212404117989261699448522029629418327941725363460257309258778728010840349285879253334717998010169995571" +
            "2783484840939943078336881900603748364853661484295815328346439461628219386259143033871942047438878967619546" +
            "7594611836361107287421865444696013355962183035465015282617378162903994666923195120420383317552390493";
    private static final String stringForG = "238515929380523934831288835701";
    private static final BigInteger p = new BigInteger(stringForp);
    private static final BigInteger g = new BigInteger(stringForG);
    private RSA rsa = new RSA();

    public BigInteger getRandomNumber(){
        Random random = new Random();
        return new BigInteger(random.nextInt(11) + "");
    }


    public BigInteger computeNumberToSend(BigInteger randomNumber){
        return g.modPow(randomNumber, p);

    }

    public BigInteger computeCommonKey(BigInteger receivedNumber, BigInteger randomNumber){
        return receivedNumber.modPow(randomNumber,p);
    }

    public BigInteger sign(KeyObject privateKey, BigInteger message){
        return rsa.sign(privateKey, message);
    }

    public boolean verify(KeyObject publicKey, BigInteger message, BigInteger signature){
        return rsa.verify(publicKey, message, signature);
    }

    public KeyObject generatePrivateKey(BigInteger e){
        return rsa.generatePrivateKey(2000,e);
    }


}
