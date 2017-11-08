/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca.tasks;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import org.bouncycastle.util.encoders.Hex;
import pv181.jca.Globals;

/**
 *
 * @author dusanklinec
 */
public class Task02MessageDigest {
    public static void main(String args[]) throws IOException {
        // 1. Obtain InputStream for web page - follow hint.
        final InputStream is01 = new URL(
                "http://www.fi.muni.cz/~xklinec/java/file_a.bin"
        ).openStream();
        
        // 2. Obtain MessageDigest instances. 
        // YOUR-CODE-GOES-HERE
        
        // 3. Read InputStream iterativelly.
        // In each iteration update the internal state of the MessageDigest
        // Allocate a temporary buffer to read data to.
        byte[] buffer = new byte[1024];

        // Read input stream by chunks.
        int bytesRead = -1;
        while ((bytesRead = is01.read(buffer)) >= 0){
                // buffer now contains bytesRead bytes of data, process it.	
                // Pay attention to a fact that read() call does not necessarily 
                // have to fill the whole buffer with a valid data!

                // TODO: do some work here.
                // e.g., update digest state, process with cipher, etc...
        }

        // Stream reading finished here.
        // Since bytesRead contains negative value it means there is no more data
        // in the stream.
        
        // 4. Compute final message digest and print it.
        // YOUR-CODE-GOES-HERE
        
        // 5. Find a difference between provided digests and computed.
        // YOUR-CODE-GOES-HERE or do manually ;)
        byte[] expectedMd5 = Hex.decode("e64db39c582fe33b35df742e8c23bd55");
    }
}
