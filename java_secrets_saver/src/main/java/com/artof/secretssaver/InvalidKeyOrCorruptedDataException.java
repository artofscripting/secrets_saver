package com.artof.secretssaver;

public class InvalidKeyOrCorruptedDataException extends Exception {
    public InvalidKeyOrCorruptedDataException() {
        super("Invalid key or corrupted data.");
    }
}
