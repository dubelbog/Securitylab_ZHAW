package ch.zhaw.securitylab.securefilestorage;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static ch.zhaw.securitylab.securefilestorage.Common.*;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Scanner;

public class SecureFileStorageServer {

    // The directory that contains the files
    private static final String FILES_DIR = "data/files/";

    // The files that contains the users (original and the one to be used)
    private static final String USERS_FILE_ORG = "data/system/users.org";
    private static final String USERS_FILE = "data/system/users";

    // The socket used to listen for incoming connections from clients
    private static ServerSocket listeningSocket;

    // The map to store issued session IDs per username
    private final Map<String,String> SESSION_IDS = new HashMap<>();

    /* Constructor */
    public SecureFileStorageServer() {
        try {
            listeningSocket = new ServerSocket(PORT);
        } catch (IOException e) {
            // If server socket cannot be created, exit
            System.out.println("ServerSocket cannot be created, exiting");
            System.exit(-1);
        }
    }

    /* This method starts the actual web server */
    private void run() {
        while (true) {

            // Wait for a connection from a client and process the request
            try {
                Socket socket = listeningSocket.accept();
                processRequest(socket);
                socket.close();
            } catch (IOException e) {
                // If accepting connections does not work, exit
                System.out.println("Connections cannot be accepted, exiting");
                System.exit(-1);
            }
        }
    }

    /* Reads the request from the client and responds accordingly */
    private void processRequest(Socket socket) {

        // fromClient and toClient are used to read data from and write data to the client
        try (BufferedReader fromClient = new BufferedReader(
                new InputStreamReader(socket.getInputStream()));
             OutputStreamWriter toClient = new OutputStreamWriter(socket.getOutputStream())) {

            // Read first line of request from the client
            String line;
            try {
                line = readLineMaxChar(fromClient, 1000);
            } catch (IOException e) {
                writeNOKNoContent(toClient);
                return;
            }

            if (line == null) {
                // Apparently, the client disconnected without sending anything, do nothing
            } else {
                // Validate the first line of the request
                if (!validateFirstLineOfRequest(line)) {
                    writeNOKNoContent(toClient);
                    return;
                }
                // System.out.println("First line of request: " + line);
                // Get request type and argument from the first line of the request
                int indexSpace = line.indexOf(' ');
                String requestType = line.substring(0, indexSpace);
                String argument = urlDecode(line.substring(indexSpace + 1));
                switch (requestType) {
                    case REGISTER:
                        register(toClient, argument);
                        break;
                    case LOGIN:
                        login(toClient, argument);
                        break;
                    case GET:
                        serveFile(fromClient, toClient, argument);
                        break;
                    case PUT:
                        storeFile(fromClient, toClient, argument);
                        break;
                    case SYSTEM:
                        executeSystemCommand(fromClient, toClient, argument);
                        break;
                    default:
                        // Unsupported request type, respond with NOK
                        writeNOKNoContent(toClient);
                        break;
                }
            }
        } catch (IOException e) {
            // An IO problem happened, ignore (stop handling request)
        }
    }

    /* register is used to perform a user registration */
    private void register(OutputStreamWriter toClient, String credentials) {

        if (!validateCredentials(credentials)) {
            writeNOKNoContent(toClient);
            return;
        }

        // If the user already exists, respond with NOK
        if (userExists(credentials)) {
            writeNOKNoContent(toClient);
            return;
        }

        // Write new credentials to users file and respond with OK
        Path file = Paths.get(USERS_FILE);
        try {
            Files.writeString(file, credentials + "\n", StandardOpenOption.APPEND);
        } catch (IOException e) {
            // ignore
        }
        writeOKNoContent(toClient);
    }

    /* login is used to perform a login, to create a session ID, and to send
       back the response to the client */
    private void login(OutputStreamWriter toClient, String credentials) {

        // If the credentials are not correct, respond with NOK
        if (!checkCredentials(credentials) || !validateCredentials(credentials)) {
            writeNOKNoContent(toClient);
            return;
        }

        /* Get the username, create a session ID, and return the session ID
           (with prepended username:) to the client */
        String[] tokens = credentials.split(":");
        String username = tokens[0];
        String sessionID = createSessionID(username);
        try {
            toClient.write(OK + "\n" + CONTENT + "\n" + username + ":" + sessionID +
                    "\n" + DONE + "\n");
        } catch (IOException e) {
            // ignore
        }
    }

    /* serveFile is used to return the content of a requested file */
    private void serveFile(BufferedReader fromClient, OutputStreamWriter toClient,
                           String filename) {
        try {
            if (!validateFilename(filename)) {
                writeNOKNoContent(toClient);
                return;
            }
            // Get the next line from the request and extract username and sessionID
            String line = readLineMaxChar(fromClient, 1000);
            // Validate the session ID
            if (!validateSessionID(line)) {
                writeNOKNoContent(toClient);
                return;
            }

            String[] tokens = line.split(":");
            String username = tokens[0];
            String sessionID = tokens[1];

            /* Check if the received sessionID is valid, i.e., if it has been
               issued by the server before. If not, respond with NOK. */
            if (!checkSessionID(sessionID, username)) {
                writeNOKNoContent(toClient);
                return;
            }

            // Read lines from file and send them to the client
            String filepath = FILES_DIR + username + "/" + filename;
            if (!validateFilepath(filepath)) {
                writeNOKNoContent(toClient);
                return;
            }
            try (BufferedReader fromFile = new BufferedReader(new FileReader(filepath))) {
                writeOKContent(toClient);
                line = fromFile.readLine();
                while (line != null) {
                    toClient.write(line + "\n");
                    line = fromFile.readLine();
                }
                toClient.write(DONE + "\n");
            }
        } catch (IOException e) {
            writeNOKNoContent(toClient);
        }
    }

    /* storeFile is used to store a file */
    private void storeFile(BufferedReader fromClient, OutputStreamWriter toClient,
                           String filename) {
        try {
            if (!validateFilename(filename)) {
                writeNOKNoContent(toClient);
                return;
            }
            // Get the next line from the request and extract username and sessionID
            String line = readLineMaxChar(fromClient, 1000);

            // Validate the session ID
            if (!validateSessionID(line)) {
                writeNOKNoContent(toClient);
                return;
            }

            String[] tokens = line.split(":");
            String username = tokens[0];
            String sessionID = tokens[1];

            /* Check if the received sessionID is valid, i.e., if it has been
               issued by the server before. If not, respond with NOK. */
            if (!checkSessionID(sessionID, username)) {
                writeNOKNoContent(toClient);
                return;
            }

            // Read lines from client and write them to the specified file
            fromClient.readLine(); // Absorb CONTENT control line
            StringBuilder fileContent = new StringBuilder();
            line = readLineMaxChar(fromClient, 1000);
            while ((line != null) && (!line.equals(DONE))) {
                if (fileContent.length() > 1000) {
                    writeNOKNoContent(toClient);
                    return;
                }
                fileContent.append(line).append("\n");
                line = readLineMaxChar(fromClient, 1000);
            }
            String filepath = FILES_DIR + username + "/" + filename;
            if (!validateFilepath(filepath)) {
                writeNOKNoContent(toClient);
                return;
            }
            try (FileWriter toFile = new FileWriter(filepath)) {
                toFile.write(fileContent.toString());
            }
            writeOKNoContent(toClient);
        } catch (IOException e) {
            writeNOKNoContent(toClient);
        }
    }

    /* Execute a command and return results to client */
    private void executeSystemCommand(BufferedReader fromClient, OutputStreamWriter toClient,
                                      String command) {
        try {
            if (!validateCommand(command)) {
                writeNOKNoContent(toClient);
                return;
            }
            // Get the next line from the request and extract username and sessionID
            String line = readLineMaxChar(fromClient, 1000);

            // Validate the session ID
            if (!validateSessionID(line)) {
                writeNOKNoContent(toClient);
                return;
            }

            String[] tokens = line.split(":");
            String username = tokens[0];
            String sessionID = tokens[1];

            /* Check if the received sessionID is valid, i.e., if it has been
               issued by the server before. If not, respond with NOK. */
            if (!checkSessionID(sessionID, username)) {
                writeNOKNoContent(toClient);
                return;
            }

            // Depending on the actual command, execute the right OS command
            int indexSpace = command.indexOf(' ');
            String actualCommand = command.substring(0, indexSpace);
            String options = command.substring(indexSpace + 1);
            if (actualCommand.equals(COMMAND_USAGE)) {
                Runtime runtime = Runtime.getRuntime();
                String[] cmd = new String[3];
                cmd[0] = "/bin/sh";
                cmd[1] = "-c";
                cmd[2] = "du -h " + FILES_DIR + username + "/" + options;
                Process proc = runtime.exec(cmd);
                Scanner reader = new Scanner(proc.getInputStream());
                StringBuilder sb = new StringBuilder();
                writeOKContent(toClient);
                while (reader.hasNextLine()) {
                    toClient.write(reader.nextLine() + "\n");
                }
                toClient.write(DONE + "\n");
            } else {
                writeNOKNoContent(toClient);
            }
        } catch (IOException e) {
            writeNOKNoContent(toClient);
        }
    }

    /* Send an OK message without additional content to the client */
    private void writeOKNoContent(OutputStreamWriter toClient) {
        try {
            toClient.write(OK + "\n" + DONE + "\n");
        } catch (IOException e) {
            // ignore
        }
    }

    /* Send a NOK message without additional content to the client */
    private void writeNOKNoContent(OutputStreamWriter toClient) {
        try {
            toClient.write(NOK + "\n" + DONE + "\n");
        } catch (IOException e) {
            // ignore
        }
    }

    /* Send an OK message with a CONTENT separator to the client */
    private void writeOKContent(OutputStreamWriter toClient) {
        try {
            toClient.write(OK + "\n" + CONTENT + "\n");
        } catch (IOException e) {
            // ignore
        }
    }

    /* Check if the user already exists  */
    private boolean userExists(String credentials) {
        Path file = Paths.get(USERS_FILE);
        String[] tokens = credentials.split(":");
        String user = tokens[0];
        try {
            List<String> allCredentials = Files.readAllLines(file);
            for (String cred : allCredentials) {
                tokens = cred.split(":");
                if (tokens[0].equals(user)) {
                    return true;
                }
            }
        } catch (IOException e) {
            // Ignore, will return false
        }
        return false;
    }

    /* Check credentials for correctness */
    private boolean checkCredentials(String credentials) {
        boolean passwordCorrect = false;
        Path file = Paths.get(USERS_FILE);
        try {
            String[] tokens = credentials.split(":");
            String username = tokens[0];
            String password = tokens[1];
            List<String> allCredentials = Files.readAllLines(file);
            for (String cred : allCredentials) {
                tokens = cred.split(":");
                if (tokens[0].equals(username) && tokens[1].equals(password)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }

    /* Create a random, 256 bits long session ID, store it in the SESSION_IDS
       map and return it */
    private String createSessionID(String username) {
        final SecureRandom secureRandom = new SecureRandom();
        String sessionID = toHexString(
                sha2_256_10000((secureRandom.generateSeed(64))));
        SESSION_IDS.put(username, sessionID);
        return sessionID;
    }

    /* Check whether sessionID is valid, i.e., whether it is in the SESSION_IDS map */
    private boolean checkSessionID(String sessionID, String username) {
        return (username!=null || sessionID != null) && sessionID.equals(SESSION_IDS.get(username));
    }

    /* URL-decode input */
    private String urlDecode(String input) {
        try {
            input = URLDecoder.decode(input, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            // Returns non-decoded input
        }
        return input;
    }

    private boolean validateFirstLineOfRequest(String input) {
        return input != null && input.matches("^(REGISTER|LOGIN|GET|PUT|SYSTEM) [\\x21-\\x7E][\\x20-\\x7E]+$");
    }
    private boolean validateSessionID(String input) {
        return input != null && input.matches("^[\\x21-\\x7E]{5,20}:[(\\x30-\\x39)|(\\x41-\\x46)]{64}");
    }

    private boolean validateFilename(String filename) {
        return filename != null && filename.matches("[a-zA-Z0-9_+=$%?,.;:]{1,50}");
    }

    private boolean validateCredentials(String credentials) {
        return credentials != null && credentials.matches("^[a-zA-Z0-9_.]{5,20}:[a-zA-Z0-9_+=$%?,.;:]{8,50}");
    }

    private boolean validateFilepath(String filepath) {
        return filepath != null && !filepath.contains("../");
    }

    private boolean validateCommand(String command) {
        return command != null && command.matches("USAGE ([*]|.)$");
    }

    private String readLineMaxChar(Reader reader, int max) throws IOException {
        StringBuilder line = new StringBuilder();
        int character;
        int counter = 0;

        while ((character = reader.read()) != '\n' && character != -1){
            counter++;
            if(counter > max) {
                throw new IOException("The input exceeds the enable file size! Please shorten your message and try one more time!");
            }
            line.append(Character.toString(character));
        }

        String output = line.toString();
        return output.equals("") ? null : output;
    }

    /* main method */
    public static void main(String argv[]) {
        try {
            // Copy original users file to the one to be used
            Files.copy(Paths.get(USERS_FILE_ORG), Paths.get(USERS_FILE),
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // If users file cannot be copied, exit
            System.out.println("Users.org cannot be copied to users, exiting");
            System.exit(-1);
        }

        // Create a SecureFileStorageServer object and run it
        (new SecureFileStorageServer()).run();
    }
}