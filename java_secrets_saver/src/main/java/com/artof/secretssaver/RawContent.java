package com.artof.secretssaver;

public class RawContent {
    public String salt;
    public String nonce;
    public String ciphertext;

    public RawContent() {
    }

    public RawContent(String salt, String nonce, String ciphertext) {
        this.salt = salt;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }
}
