package com.github.tokoko.oidc;

import com.github.tokoko.oidc.exceptions.AuthenticationException;
import com.github.tokoko.oidc.exceptions.CLINotFoundException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

public class CliRunner {

    private static final String ENV_CLI_PATH = "OIDC_CLI_PATH";

    String findOidcBinary() {
        String envPath = System.getenv(ENV_CLI_PATH);
        if (envPath != null && !envPath.isEmpty()) {
            Path p = Path.of(envPath);
            if (Files.isRegularFile(p) && Files.isExecutable(p)) {
                return envPath;
            }
            throw new CLINotFoundException(
                ENV_CLI_PATH + "=" + envPath + " does not point to an executable file"
            );
        }

        String pathEnv = System.getenv("PATH");
        if (pathEnv != null) {
            String binaryName = isWindows() ? "oidc.exe" : "oidc";
            for (String dir : pathEnv.split(File.pathSeparator)) {
                Path candidate = Path.of(dir, binaryName);
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                    return candidate.toString();
                }
            }
        }

        throw new CLINotFoundException(
            "Could not find 'oidc' binary. Install it or set " + ENV_CLI_PATH + "."
        );
    }

    public void runInit(String profile) {
        runInit(profile, 0);
    }

    public void runInit(String profile, long timeoutSeconds) {
        String binary = findOidcBinary();
        ProcessBuilder pb = new ProcessBuilder(binary, "init", "--profile", profile)
            .inheritIO();

        try {
            Process process = pb.start();
            boolean finished;
            if (timeoutSeconds > 0) {
                finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
                if (!finished) {
                    process.destroyForcibly();
                    throw new AuthenticationException(
                        "oidc init timed out after " + timeoutSeconds + " seconds"
                    );
                }
            } else {
                process.waitFor();
            }
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                throw new AuthenticationException(
                    "oidc init failed with exit code " + exitCode
                );
            }
        } catch (IOException e) {
            throw new CLINotFoundException("Failed to execute: " + binary, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthenticationException("oidc init was interrupted", e);
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }
}
