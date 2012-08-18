
public class Test
{
    public static void main(String [] args) throws Exception
    {
        byte[] x = new byte[16];
        byte[] z = new byte[16];

        System.in.read(z);
        AES aes = new AES(z);

        while(System.in.read(x) != -1)
            System.out.write(aes.decrypt(aes.encrypt(x)));
    }
}
