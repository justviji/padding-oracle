import it.exploit.socket.Connection;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class PaddingOracleAttack {

    public static byte[] getBlock(int blockIndex, byte[] ciphertext) {
        int start = blockIndex * 16;
        int end = (blockIndex + 1) * 16;
        return Arrays.copyOfRange(ciphertext, start, end);
    }
    public static byte[][] getAllBlocks(byte[] ciphertext) {
        int numBlocks = ciphertext.length / 16;
        byte[][] allBlocks = new byte[numBlocks][];

        for (int blockIndex = 0; blockIndex < numBlocks; blockIndex++) {
            allBlocks[blockIndex] = getBlock(blockIndex, ciphertext);
        }

        return allBlocks;
    }

    public static void main(String[] args){

        String ipAddress = "10.10.30.38";
        int port = 7007;
        int blockSize = 16;
        try (Connection serverConnection = new Connection(ipAddress, port).connect()) {
            for (byte[] block : getAllBlocks(serverConnection.read().getText().getBytes())) {
                byte[] decryptedBlock = new byte[16]; //decrypt ecery message one by one
                StringBuilder decryptedMessage = new StringBuilder();
                for (int pointer = 0x15; pointer >= 0x00; pointer--) { //moves the pointer one by one for all 16 different positions
                    for (int guess = 0; guess < 255; guess++) { // guesses the last byte

                        try {
                            //last byte of previous message xor guess xor 0x01
                            byte tryDecrypt = (byte) (block[blockSize - 1] ^ (byte) guess ^ (byte) pointer);
                            //string builder to build a valid message (not necessary)
                            StringBuilder finalMessageForOracle = new StringBuilder();
                            //cant know this block so ill just send it off
                            finalMessageForOracle.append(Arrays.toString(getBlock(0, serverConnection.read().getText().getBytes())));
                            //sets the bytes of the pointer to the new
                            decryptedBlock[pointer] = tryDecrypt;
                            finalMessageForOracle.append(Arrays.toString(decryptedBlock));
                            //another random block after that -> the attack looks like this for the first index messageSent(mB[0], mB'[1], mB[2])
                            finalMessageForOracle.append(Arrays.toString(getBlock(2, serverConnection.read().getText().getBytes())));
                            if (serverConnection.write(finalMessageForOracle.toString()).read().getText().equals("OK!")) {
                                break;
                            }
                            //ignore the index out of bounds for the first value
                        } catch (IndexOutOfBoundsException ignored) {}
                    }
                }
                decryptedMessage.append(Arrays.toString(decryptedBlock));
            }

        }catch (Exception e){
            System.out.println("Error with the server connection: "+ Arrays.toString(e.getStackTrace()));
        }
    }

}
