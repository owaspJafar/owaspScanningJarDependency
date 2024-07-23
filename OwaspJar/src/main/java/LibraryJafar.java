import com.sun.tools.javac.Main;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Objects;

/**
 * This is a sample class for the Library.
 */
public class LibraryJafar {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Main.class);


    public static void main(String[] args) {

        // dependencyCheckAnalyze();
    }


    /**
     * Enter the name of the Library dependency and let it scan
     */
    public static void scanLibrary(String nameLibrary) {
        ArrayList<String> listLib=new ArrayList<>();
        listLib.addAll(reportJsonParserJafar());
        logger.info("\n\n\n\n\n");


        boolean isVulnerable = false;
        for (String item : listLib) {
            if (item.contains(nameLibrary)) {
                isVulnerable = true;
                break;
            }
        }


        if (isVulnerable){
            logger.info("OWASP scanning jafar: "+nameLibrary +"---------> This library is vulnerable");
        }else {
            logger.info("OWASP scanning jafar: "+nameLibrary +"---------> This library is not vulnerable");
        }
    }

    /**
     * Displaying reports in Logcat
     */
    public static void showReportLogCat() {

        String filename = "build/reports/dependency-check-report.html";
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    /**
     * Analyzing the Jason file and separating vulnerable and invulnerable libraries
     *
     * @return
     */
    public static ArrayList<String> reportJsonParserJafar( ){
        if (readFile()!=null) {
            JSONObject jsonObject = new JSONObject(Objects.requireNonNull(readFile()));
            JSONArray dependencies = jsonObject.getJSONArray("dependencies");
            logger.info("OWASP scanning jafar: List of books that are vulnerable");
            ArrayList<String> listNot = new ArrayList<>();
            ArrayList<String> listVulnerabilities = new ArrayList<>();
            for (int i = 0; i < dependencies.length(); i++) {
                JSONObject dependenciesJsonObject = dependencies.getJSONObject(i);
                try {
                    if (dependenciesJsonObject.has("vulnerabilities") && dependenciesJsonObject.get("vulnerabilities") instanceof JSONArray) {
                        JSONArray vulnerabilities = dependenciesJsonObject.getJSONArray("vulnerabilities");
                        String severity = vulnerabilities.getJSONObject(0).getString("severity");
                        String fileName = dependenciesJsonObject.getString("fileName");
                        listVulnerabilities.add(fileName);
                        logger.info("OWASP scanning jafar:\t" + fileName + "\t-------------------->      Highest Severity = " + severity);
                    } else {
                        String fileName = dependenciesJsonObject.getString("fileName");
                        listNot.add("OWASP scanning jafar:\t" + fileName);
                    }
                } catch (Exception e) {
                    System.out.println(" " + e.getMessage());
                    e.fillInStackTrace();
                }
            }
            logger.info("\n\n\n");
            logger.info("OWASP scanning jafar: List of books that are not vulnerable");
            for (String s : listNot) {
                logger.info(s);
            }
            return listVulnerabilities;
        }
        return null;
    }
    /**Reading the report.json file*/
    private static String readFile( ) {
        String filePath="build/jafar-report/dependency-check-report.json";
        StringBuilder content = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                content.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return content.toString();
    }

    public static void showReportJsonLogCat() {

        String filename = "build/jafar-report/dependency-check-report.json";
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            StringBuilder result = new StringBuilder();
            while ((line = br.readLine()) != null) {
                result.append(line);
                //  System.out.println(line);
            }

            JSONObject jsonObject = new JSONObject(result);

            System.out.println(jsonObject);
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    /**
     * This runShellCommand method is used to execute terminal commands such as: git init
     */
    public static void runShellCommand(String command) {
        Process process;
        try {
            process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("Command executed successfully:");

            } else {
                System.out.println("Command execution failed with code:");
            }

        } catch (Exception e) {
            System.out.println("runShellCommand:");
            e.fillInStackTrace();
        }
    }

    /**
     * This runShellCommandGradlew method takes a string from the user,
     * which can be anything.
     * Like : ./gradlew dependencyCheckAnalyze
     */
    public static void runShellCommandGradlew(String command) {
        String os = System.getProperty("os.name").toLowerCase();
        ProcessBuilder processBuilder = new ProcessBuilder();
        if (os.contains("win")) {
            // If on Windows, use cmd.exe and gradlew.bat
            processBuilder.command("cmd.exe", "/c", command.replace("./gradlew", "gradlew.bat"));
        } else {
            // If on Unix-like system, use bash
            processBuilder.command("bash", "-c", command);
        }
        try {
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            while ((line = errorReader.readLine()) != null) {
                System.err.println(line);
            }
            int exitCode = process.waitFor();
            System.out.println("\nExited with code: " + exitCode);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates various reports that include details of detected vulnerabilities,
     * the extent of the risk, and suggested solutions to fix them.
     */
    public static void dependencyCheckAnalyze() {
        runShellCommandGradlew("./gradlew dependencyCheckAnalyze");
    }

    /**
     * Updating the database is necessary to identify new vulnerabilities and
     * improve the accuracy of the analysis.
     */
    public static void dependencyCheckUpdate() {
        runShellCommandGradlew("./gradlew dependencyCheckUpdate");
    }

    /**
     * This command clears the local database of vulnerabilities.
     * This is useful when you want to update the local database from scratch.
     */
    public static void dependencyCheckPurge() {
        runShellCommandGradlew("./gradlew dependencyCheckPurge");
    }

    /**
     * This command creates a consolidated report of several projects in a multi-project.
     * For projects that contain multiple modules, this command provides an overall report.
     */
    public static void dependencyCheckAggregate() {
        runShellCommandGradlew("./gradlew dependencyCheckAggregate");
    }

    /**
     * This command is similar to dependencyCheckAnalyze,
     * but runs with a higher information level that provides more detail in the output.
     * This is useful for debugging and more detailed analysis.
     */
    public static void dependencyCheckAnalyzeInfo() {
        runShellCommandGradlew("./gradlew dependencyCheckAnalyze --info");
    }

    /**
     * This command is similar to dependencyCheckAnalyze but with the scan feature,
     * which provides additional information about the analysis process and dependencies.
     */
    public static void dependencyCheckAnalyzeScan() {
        runShellCommandGradlew("./gradlew dependencyCheckAnalyze --scan");
    }
}


