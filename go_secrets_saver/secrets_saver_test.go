package secretssaver

import (
    "errors"
    "fmt"
    "path/filepath"
    "testing"
    "time"
)

func fixedPrompt(pass string) PromptFunc {
    return func(string) (string, error) {
        return pass, nil
    }
}

func testPasswords() (string, string) {
    base := fmt.Sprintf("test-%d", time.Now().UnixNano())
    return base, base + "-wrong"
}

func TestSetGetListClear_FileBackend(t *testing.T) {
    tmp := t.TempDir()
    file := filepath.Join(tmp, "secrets.ep")
    goodPass, _ := testPasswords()

    s, err := New(file, nil, fixedPrompt(goodPass))
    if err != nil {
        t.Fatalf("New failed: %v", err)
    }

    if err := s.SetSecret("a", "1"); err != nil {
        t.Fatalf("SetSecret(a) failed: %v", err)
    }
    if err := s.SetSecret("b", "2"); err != nil {
        t.Fatalf("SetSecret(b) failed: %v", err)
    }

    got, ok, err := s.GetSecret("a")
    if err != nil {
        t.Fatalf("GetSecret failed: %v", err)
    }
    if !ok || got != "1" {
        t.Fatalf("unexpected GetSecret result: got=%q ok=%v", got, ok)
    }

    keys, err := s.ListSecrets()
    if err != nil {
        t.Fatalf("ListSecrets failed: %v", err)
    }
    if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
        t.Fatalf("unexpected keys: %#v", keys)
    }

    if err := s.ClearDatabase(); err != nil {
        t.Fatalf("ClearDatabase failed: %v", err)
    }

    keys, err = s.ListSecrets()
    if err != nil {
        t.Fatalf("ListSecrets after clear failed: %v", err)
    }
    if len(keys) != 0 {
        t.Fatalf("expected empty keys after clear, got: %#v", keys)
    }
}

func TestInvalidKey(t *testing.T) {
    tmp := t.TempDir()
    file := filepath.Join(tmp, "secrets.ep")
    goodPass, badPass := testPasswords()

    writer, err := New(file, nil, fixedPrompt(goodPass))
    if err != nil {
        t.Fatalf("writer New failed: %v", err)
    }
    if err := writer.SetSecret("x", "y"); err != nil {
        t.Fatalf("writer SetSecret failed: %v", err)
    }

    reader, err := New(file, nil, fixedPrompt(badPass))
    if err != nil {
        t.Fatalf("reader New failed: %v", err)
    }

    _, _, err = reader.GetSecret("x")
    if err == nil {
        t.Fatal("expected error for invalid key")
    }
    if !errors.Is(err, ErrInvalidKeyOrCorruptedData) {
        t.Fatalf("expected ErrInvalidKeyOrCorruptedData, got: %v", err)
    }
}

