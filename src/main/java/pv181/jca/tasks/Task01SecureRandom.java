/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca.tasks;

import java.security.SecureRandom;
import pv181.jca.Globals;

/**
 *
 * @author dusanklinec
 */
public class Task01SecureRandom {
    public static void main(String args[]) {
        /**
         * Hint 1: Use CTRL+SHIFT+I to automatically add missing imports.
         * Hint 2: Use System.out.printn("TEST"); in order to print something on the terminal.
         * Hint 3: In order to execute code in this file, right click on a file 
         * in the left panel and select "Run".
         */
        
        // This way you initialize a new byte[] with specified size.
        byte[] buffer = new byte[1024];
        
        // Initialize secure random instance here.
        SecureRandom rand = null;  // TODO: init, YOUR-CODE-GOES-HERE
        
        // Fill buffer with random bytes.
        // YOUR-CODE-GOES-HERE
        
        // Print buffer with Globals.bytesToHexString()
        System.out.println("Random bytes: \n" + Globals.bytesToHexString(buffer));
    }   
}
