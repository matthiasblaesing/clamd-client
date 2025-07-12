
import eu.doppelhelix.lib.clamdclient.ClamdClient;
import java.io.FileInputStream;
import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ManualTest {

    public static void main(String[] args) throws IOException {
        ClamdClient client = new ClamdClient("/var/run/clamav/clamd.ctl");

        System.out.println(client.scanStream("Dummy".getBytes()));
        System.out.println(client.scanStream(("X5O!P%@AP[4\\PZX54(P^)7CC" + ")7}$EICAR-STANDARD-ANTIVIRUS" + "-TEST-FILE!$H+H*").getBytes(UTF_8)));

        try (FileInputStream fis = new FileInputStream("/home/matthias/test")) {
            System.out.println(client.scanStream(fis));
        }

        try (FileInputStream fis = new FileInputStream("/home/matthias/Downloads/eicar.com.txt")) {
            System.out.println(client.scanStream(fis));
        }

        try (FileInputStream fis = new FileInputStream("/home/matthias/Downloads/eicar_com.zip")) {
            System.out.println(client.scanStream(fis));
        }

        try (FileInputStream fis = new FileInputStream("/home/matthias/Downloads/virustest/Friday_the_13th.540.A.com")) {
            System.out.println(client.scanStream(fis));
        }

        try (FileInputStream fis = new FileInputStream("/home/matthias/img1000")) {
            System.out.println(client.scanStream(fis));
        }
    }
}
