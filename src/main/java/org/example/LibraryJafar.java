package org.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * This is a sample class for the Library.
 */
public class LibraryJafar {


    public static void main(String[] args) {

        dependencyCheckAnalyze();
    }

    /**Enter the name of the Library dependency and let it scan*/
    public static void scanLibrary(){
        //Coming Soon
        /**/
    }

    /**Displaying reports in Logcat*/
    public static void showReportLogCat(){

        String filename =  "build/reports/dependency-check-report.html"; // مسیر فایل مورد نظر درون پوشه libs
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line); // یا هر کار دیگری که می‌خواهید با خطوط فایل انجام دهید
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    /**This runShellCommand method is used to execute terminal commands such as: git init*/
    public static void runShellCommand(String command) {
        Process process;
        try {
            process = Runtime.getRuntime().exec(command);
            // خواندن خروجی دستور
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();

            // بررسی کد خروجی
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

    /**This runShellCommandGradlew method takes a string from the user,
     *  which can be anything.
     *  Like : ./gradlew dependencyCheckAnalyze*/
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


    /**Generates various reports that include details of detected vulnerabilities,
     *  the extent of the risk, and suggested solutions to fix them.*/
    public static void dependencyCheckAnalyze(){
        runShellCommandGradlew("./gradlew dependencyCheckAnalyze");
    }

    /**Updating the database is necessary to identify new vulnerabilities and
     * improve the accuracy of the analysis.*/
    public static void dependencyCheckUpdate(){
        runShellCommandGradlew("./gradlew dependencyCheckUpdate");
    }

    /**This command clears the local database of vulnerabilities.
     *  This is useful when you want to update the local database from scratch.*/
    public static void dependencyCheckPurge(){
        runShellCommandGradlew("./gradlew dependencyCheckPurge");
    }

    /**This command creates a consolidated report of several projects in a multi-project.
     *  For projects that contain multiple modules, this command provides an overall report.*/
    public static void dependencyCheckAggregate(){
        runShellCommandGradlew("./gradlew dependencyCheckAggregate");
    }

    /**This command is similar to dependencyCheckAnalyze,
     *  but runs with a higher information level that provides more detail in the output.
     *  This is useful for debugging and more detailed analysis.*/
    public static void dependencyCheckAnalyzeInfo(){
        runShellCommandGradlew("./gradlew dependencyCheckAnalyze --info");
    }

    /**This command is similar to dependencyCheckAnalyze but with the scan feature,
     *  which provides additional information about the analysis process and dependencies.*/
    public static void dependencyCheckAnalyzeScan(){
        runShellCommandGradlew("./gradlew dependencyCheckAnalyze --scan");
    }
}



