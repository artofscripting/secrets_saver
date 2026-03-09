package com.artof.secretssaver;

public interface DatabaseAdapter {
    RawContent readEncryptedRow() throws Exception;

    void upsertEncryptedRow(RawContent content) throws Exception;
}
