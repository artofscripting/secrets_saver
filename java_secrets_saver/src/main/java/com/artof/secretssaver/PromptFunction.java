package com.artof.secretssaver;

@FunctionalInterface
public interface PromptFunction {
    String prompt(String location) throws Exception;
}
