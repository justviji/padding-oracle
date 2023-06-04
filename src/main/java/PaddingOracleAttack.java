import it.exploit.socket.Connection;

import java.util.Arrays;

public class PaddingOracleAttack {
    /**
     *
     * @param blockIndex index of the binary block. every block is 16 long
     * @param ciphertext the binary array that the block has to be extracted from
     * @return the start of the block to the end of the next block
     */

    public static byte[] getBlock(int blockIndex, byte[] ciphertext) {
        int start = blockIndex * 16;
        int end = (blockIndex + 1) * 16;
        return Arrays.copyOfRange(ciphertext, start, end);
    }

    /**
     *
     * @param ciphertext gets all the single block from the given byte array
     * @return all the single blocks in an array of blocks
     */
    public static byte[][] getAllBlocks(byte[] ciphertext) {
        int numBlocks = ciphertext.length / 16;
        byte[][] allBlocks = new byte[numBlocks][];
        for (int blockIndex = 0; blockIndex < numBlocks; blockIndex++) {
            allBlocks[blockIndex] = getBlock(blockIndex, ciphertext);
        }
        return allBlocks;
    }

    /**
     * @param args is ignored and not used
     * sets up connection to the server and writes it
     */
    
    public static void main(String[] args) {
        String ipAddress = "10.10.30.38";
        int port = 7007;
        int blockSize = 16;
        try (Connection serverConnection = new Connection(ipAddress, port).connect()) {
            byte[] ciphertext = serverConnection.read().getText().getBytes();
            byte[][] allBlocks = getAllBlocks(ciphertext);

            for (int blockIndex = 0; blockIndex < allBlocks.length; blockIndex++) {
                byte[] decryptedBlock = new byte[blockSize];
                for (int pointer = blockSize - 1; pointer >= 0; pointer--) {
                    for (int guess = 0; guess < 256; guess++) {
                        try {
                            byte[] modifiedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);
                            //previous block XOR guess XOR pointer of the array from 0 to 15
                            modifiedCiphertext[blockIndex * blockSize - 1] = (byte) (modifiedCiphertext[blockIndex * blockSize - 1] ^ (byte) guess ^ (byte) (pointer + 1));
                            serverConnection.write(Arrays.toString(modifiedCiphertext)); // write to server
                            String response = serverConnection.read().getText();
                            // Check if thge paddings right with the server message is ok
                            if (response.equals("OK!")) {
                                // Update the decrypted block with the correct byte
                                decryptedBlock[pointer] = (byte) (guess ^ (byte) (pointer + 1));
                                break;
                            }
                        } catch (Exception ignored) {}
                    }
                }
                System.out.println("Decrypted Block " + blockIndex + ": " + Arrays.toString(decryptedBlock));
            }
        } catch (Exception e) {
            System.out.println("Error with the server connection: " + Arrays.toString(e.getStackTrace()));
        }
    }
}
