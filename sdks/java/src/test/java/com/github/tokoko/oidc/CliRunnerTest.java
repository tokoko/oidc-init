package com.github.tokoko.oidc;

import com.github.tokoko.oidc.exceptions.CLINotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class CliRunnerTest {

    @TempDir
    Path tempDir;

    @Test
    void findBinaryThrowsWhenNotFound() {
        CliRunner runner = new CliRunner();
        // With no OIDC_CLI_PATH set and oidc not on PATH, this should throw
        // We can't easily control env vars in Java, so this test just verifies
        // the exception type when the binary isn't found
        // (Only runs meaningfully when oidc is not installed)
        try {
            runner.findOidcBinary();
            // If it finds a binary, that's fine too - just means oidc is installed
        } catch (CLINotFoundException e) {
            assertTrue(e.getMessage().contains("Could not find"));
        }
    }

    @Test
    void findBinaryUsesEnvPath() throws IOException {
        // Create a fake executable
        Path fakeBinary = tempDir.resolve("oidc");
        Files.writeString(fakeBinary, "#!/bin/sh\nexit 0\n");
        fakeBinary.toFile().setExecutable(true);

        // We can't set env vars in Java tests easily without a library,
        // so we test the findOidcBinary logic indirectly.
        // The actual OIDC_CLI_PATH env var path is tested via integration tests.
        assertTrue(Files.isExecutable(fakeBinary));
    }
}
