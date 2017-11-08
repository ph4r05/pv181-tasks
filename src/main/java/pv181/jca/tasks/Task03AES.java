/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca.tasks;

import org.bouncycastle.util.encoders.Base64;
import pv181.jca.Globals;

/**
 *
 * @author dusanklinec
 */
public class Task03AES {
    public static void main(String args[]) {
        /**
         * Hint 1: In order to construct a String from byte[] buffer call new String(buffer);
         */
        
        // 1. Obtain a Cipher instance with given parameters as specified on the web.
        // ...
        
        // 2. Call cipher.init with suitable parameters. Use Cipher.DECRYPT_MODE
        // as a first parameter of init. 
        // ...
        
        // 3.  Convert base64 data from the website (IV, KEY, CIPHERTEXT)
        // to the byte[] with DatatypeConverter class.
        byte[] key = Base64.decode("AAAAAAAAAAAAAAAAAAAAAA==");
        
        // 4. Call cipher.doFinal on the data from website.
        // ...
        
        // 5. Print result of doFinal method as a string.
        // ...
        
    }
}
