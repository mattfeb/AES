public interface AbstractAES 
{
    // public AES(byte[] z);
    public byte[] encrypt(byte[] x);
    public byte[] decrypt(byte[] y);
}