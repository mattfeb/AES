import java.io.*;
import java.util.Scanner;

public class AES implements AbstractAES
{
    private int current;
    private static int[] invSBox = new int[256];
    private static int[] sBox = new int[256];
    private static int Nb = 4;
    private int Nk;
    private int Nr;
    private int[][][] s = new int[2][4][4];
    private int[] w;
    private static int[][]gf = {{2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2}};
    private static int[][]invgf = {{0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}};
    private static int[] rcon = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 
        0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
        0xAB000000, 0x4D000000, 0x9A000000};

    // Constructs an AES cipher using a specific key
    public AES(byte[] z) throws Exception
    {
        Nk = z.length / 4;
        Nr = Nb + Nk + 2;
        w = new int[Nb*(Nr+1)];

        fillSubBytes();
        keyExpand(z);
    }

    // Encrypts a 128-bit (16-byte) plaintext block using this AES cipher
    public byte[] encrypt(byte[] x)
    {

        if(x.length != Nb*4) 
            throw new IllegalArgumentException("Illegal block length");

        int n = 0;
        current = 0;

        for(int i = 0 ; i < 4 ; i++)
        {
            for(int j = 0 ; j < 4 ; j++)
            {
                s[current][j][i] = ((x[n] << 24)>>>24);
                n++;
            }
        }

        addRoundKey(s[current], 0);


        for(int i = 1 ; i < Nr ; i++)
        {
            subBytes(s[current]);
            shiftRows(s[current]);
            mixColumns(s);
            current ^= 1;
            addRoundKey(s[current], i);

        }

        subBytes(s[current]);
        shiftRows(s[current]);
        addRoundKey(s[current], Nr);

        n = 0;
        for(int i = 0 ; i < 4 ; i++)
        {
            for(int j = 0 ; j < 4 ; j++)
            {
                x[n] = (byte) (((s[current][j][i]) << 24)>>>24);
                n++;
            }
        }

        return x;
    }

    // Decrypts a 128-bit (16-byte) ciphertext block using this AES cipher
    public byte[] decrypt(byte[] y)
    {
        if(y.length != Nb*4) 
            throw new IllegalArgumentException("Illegal block length");

        int n = 0;
        current = 0;
        for(int i = 0 ; i < 4 ; i++)
        {
            for(int j = 0 ; j < 4 ; j++)
            {
                s[current][j][i] = ((y[n] << 24)>>>24);
                n++;
            }
        }

        addRoundKey(s[current], Nr);

        for(int i = Nr-1 ; i > 0 ; i--)
        {
            invShiftRows(s[current]);
            invSubBytes(s[current]);
            addRoundKey(s[current], i);
            invMixColumns(s);
            current ^= 1;
        }

        invShiftRows(s[current]);
        invSubBytes(s[current]);
        addRoundKey(s[current], 0);

        n = 0;
        for(int i = 0 ; i < 4 ; i++)
        {
            for(int j = 0 ; j < 4 ; j++)
            {
                y[n] = (byte) (((s[current][j][i]) << 24)>>>24);
                n++;
            }
        }

        return y;
    }

    // Adds the key schedule for a round to a state matrix
    private int[][] addRoundKey(int[][] s, int round)
    {
        int l = round * Nb;
        int word = 0;

        for(int i = 0 ; i < 4 ; i++)
        {
            for(int j = 0 ; j < 4 ; j++)
            {
                word = w[l+i];
                s[i][j] ^= (word << (j*8)) >>> 24;
            }
        }
        return s;
    }

    // Unmixes each column of a state matrix
    private int[][] invMixColumns(int[][][] s)
    {	
        int sum = 0;

        for(int n = 0 ; n < Nb ; n++)
        {
            for(int i = 0 ; i < 4 ; i++) 
            {
                sum = 0;
                for(int j = 0 ; j < 4 ; j++)
                {
                    sum = (sum ^ mult(s[current][j][i], invgf[n][j]));
                }
                s[current^1][n][i] = sum;
            }
        }
        return s[current^1];
    }

    // Applies an inverse cyclic shift to the last 3 rows of a state matrix
    private int[][] invShiftRows(int [][] s)
    {
        int temp1 = 0, temp2 = 0;

        for(int j = 0 ; j < Nb ; j+=4)
        {
            for(int i = 1 ; i < 4 ; i++)
            {
                switch(i)
                {
                    case 1: temp1 = s[i][j+3];
                            s[i][j+3] = s[i][j+2];
                            s[i][j+2] = s[i][j+1];
                            s[i][j+1] = s[i][j];
                            s[i][j] = temp1;
                            break;
                    case 2: temp1 = s[i][j];
                            temp2 = s[i][j+1];
                            s[i][j] = s[i][j+2];
                            s[i][j+1] = s[i][j+3];
                            s[i][j+2] = temp1;
                            s[i][j+3] = temp2;
                            break;
                    case 3: temp1 = s[i][j];
                            s[i][j] = s[i][j+1];
                            s[i][j+1] = s[i][j+2];
                            s[i][j+2] = s[i][j+3];
                            s[i][j+3] = temp1;
                            break;
                }
            }
        }
        return s;
    }

    // Applies inverse S-Box substitution to each byte of a state matrix
    private static int[][] invSubBytes(int[][] s)
    {
        int temp = 0;

        for(int i = 0 ; i < 4 ; i++)
        {
            for(int j = 0 ; j < Nb ; j++)
            {
                temp = s[i][j];
                s[i][j] = invSBox[temp];
            }
        }

        return s;
    }

    // Mixes each column of a state matrix
    private int[][] mixColumns(int[][][] s)
    {
        int sum = 0;
        for(int n = 0 ; n < Nb ; n++)
        {
            for(int i = 0 ; i < 4 ; i++) 
            {
                sum = 0;
                for(int j = 0 ; j < 4 ; j++)
                {
                    sum = (sum ^ mult(s[current][j][i], gf[n][j]));
                }
                s[current^1][n][i] = sum;
            }
        }
        return s[current^1];
    }

    // Multiplies two polynomials a(x), b(x)
    private static int mult(int a, int b)
    {
        int sum = 0;
        int n = 0;

        for(int i = 0 ; i < 8 ; i++)
        {
            if((b << 31) >>> 31 == 1)
                sum ^= a;

            n = (a & 0x80);
            a <<= 1;

            if(n == 0x80)
                a ^= 0x1b;

            b >>>= 1;
        }
        return sum & 0xff;
    }

    // Applies a cyclic shift to the last 3 rows of a state matrix
    private int[][] shiftRows(int[][] s)
    {
        int temp1 = 0, temp2 = 0;

        for(int j = 0 ; j < Nb ; j+=4)
        {
            for(int i = 1 ; i < 4 ; i++)
            {
                switch(i)
                {
                    case 1: temp1 = s[i][j];
                            s[i][j] = s[i][j+1];
                            s[i][j+1] = s[i][j+2];
                            s[i][j+2] = s[i][j+3];
                            s[i][j+3] = temp1;
                            break;
                    case 2: temp1 = s[i][j];
                            temp2 = s[i][j+1];
                            s[i][j] = s[i][j+2];
                            s[i][j+1] = s[i][j+3];
                            s[i][j+2] = temp1;
                            s[i][j+3] = temp2;
                            break;
                    case 3: temp1 = s[i][j+3];
                            s[i][j+3] = s[i][j+2];
                            s[i][j+2] = s[i][j+1];
                            s[i][j+1] = s[i][j];
                            s[i][j] = temp1;
                            break;
                }
            }
        }
        return s;
    }

    // Applies S-Box substitution to each byte of a state matrix
    private static int[][] subBytes(int[][] s)
    {
        int temp = 0;

        for(int i = 0 ; i < 4 ; i++)
        {
            for(int j = 0 ; j < Nb ; j++)
            {
                temp = s[i][j];
                s[i][j] = sBox[temp];
            }
        }

        return s;
    }

    // Applies S-box substitution to each byte of a 4-byte word
    private static int subWord(int w)
    {
        int a0 = sBox[w >>> 24] <<24;
        int a1 = sBox[(w << 8) >>> 24] << 16;
        int a2 = sBox[(w << 16) >>> 24] << 8;
        int a3 = sBox[(w << 24) >>> 24];

        return a0 & a1 & a2 & a3;
    }

    // Applies a cyclic permutation to a 4-byte word
    private static int rotWord(int w) { return Integer.rotateLeft(w, 8); }

    // Expands byte array to an array w
    private int[] keyExpand(byte[] key)
    {
        int temp, i = 0;

        while(i < Nk)
        {
            int a0 = key[4*i] << 24;
            int a1 = key[4*i+1] << 24 >>> 8;
            int a2 = key[4*i+2] << 24 >>> 16;
            int a3 = key[4*i+3] << 24 >>> 24;
            w[i] = (a0) + (a1) + (a2) + a3; 
            i++;
        }

        i = Nk;
        while(i < Nb*(Nr+1))
        {
            temp = w[i-1];

            if(i % Nk == 0)
                temp = subWord(rotWord(temp)) ^ rcon[(i/Nk) - 1];
            else if(Nk > 6 && (i % Nk) == 4)
                temp = subWord(temp);
            w[i] = (w[i-Nk] ^ temp);
            i++;
        }
        return w;
    }

    // creates two arrays filled with subBytes/invSubBytes 
    private void fillSubBytes() throws Exception
    {
        // Two files containing the subbytes/invsubbytes table
        Scanner sc = new Scanner(new File("subBytesTable.txt"));
        for(int i = 0 ; i < sBox.length ; i++)
            sBox[i] = Integer.parseInt(sc.next(), 16);
        sc.close();

        sc = new Scanner(new File("invSubBytesTable.txt"));
        for(int i = 0 ; i < invSBox.length ; i++)
            invSBox[i] = Integer.parseInt(sc.next(), 16);
        sc.close();
    }
}

