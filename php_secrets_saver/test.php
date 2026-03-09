<?php

declare(strict_types=1);

require __DIR__ . '/src/SecretsSaver.php';

use SecretsSaver\InvalidKeyOrCorruptedDataException;
use SecretsSaver\SecretsSaver;

$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'secrets-saver-php-' . bin2hex(random_bytes(8));
mkdir($dir, 0777, true);
$file = $dir . DIRECTORY_SEPARATOR . 'secrets.ep';

try {
    $master = getenv('SS_MASTER_KEY');
    if ($master === false || $master === '') {
        fwrite(STDOUT, 'Enter test master key: ');
        $line = fgets(STDIN);
        $master = $line === false ? '' : trim($line);
    }

    $wrong = $master . '-wrong';

    $writer = SecretsSaver::newFile($file, static fn(string $location): string => $master);
    $writer->setSecret('a', '1');
    $writer->setSecret('b', '2');

    if ($writer->getSecret('a') !== '1') {
        throw new RuntimeException('Expected value 1 for key a.');
    }

    $keys = $writer->listSecrets();
    if (implode(',', $keys) !== 'a,b') {
        throw new RuntimeException('Unexpected keys list.');
    }

    $writer->clearDatabase();
    if (count($writer->listSecrets()) !== 0) {
        throw new RuntimeException('Expected empty key list after clear.');
    }

    $writer->setSecret('x', 'y');
    $reader = SecretsSaver::newFile($file, static fn(string $location): string => $wrong);

    $thrown = false;
    try {
        $reader->getSecret('x');
    } catch (InvalidKeyOrCorruptedDataException $e) {
        $thrown = true;
    }

    if (!$thrown) {
        throw new RuntimeException('Expected InvalidKeyOrCorruptedDataException for wrong key.');
    }

    fwrite(STDOUT, "php_secrets_saver tests passed\n");
} finally {
    if (is_file($file)) {
        @unlink($file);
    }
    @rmdir($dir);
}
