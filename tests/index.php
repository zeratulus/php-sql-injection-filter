<?php

use Ninja\DB\SqlInjection\Filter as SqlInjectionFilter;

require_once '../vendor/autoload.php';

function consoleLog(string $msg): void
{
    echo date('Y-m-d H:i:s') . " -> $msg \r\n";
}

/**
 * returns array ['1', 'string to analyze'] according to dataset, where
 * element [0] - number that means is SQL injection present in following string, if 1 - present, if 0 - just a data
 * and element [1] - string that may contain SQL injection
 **/
function prepareLine(string $str): array
{
    return [
        (bool)substr($str, 0, 1),
        substr($str, 2, strlen($str))
    ];
}

header('Content-type: text\plain; charset: utf-8;');

$currentDir = __DIR__;

$filter = new SqlInjectionFilter();
$filter->init();

$files = glob("$currentDir/dataset/*.txt");
foreach ($files as $file) {
    $lineCounter = 0;

    $fileHandler = fopen($file, 'r');
    consoleLog("Processing file: $file");
    while (($line = fgets($fileHandler)) !== false) {
        $data = prepareLine($line);
        consoleLog("Line #$lineCounter " . ($data[0] ? 'contain' : 'not contain') . " SQL injection." );
        consoleLog(" - Analyzing: $data[1]");
        if ($filter->check($data[1]) &&
            (!empty($filter->getIssues()['strings']) || !empty($filter->getIssues()['regexps']))
        ) {
            consoleLog(" - Detected problems: ");
            echo print_r($filter->getIssues(), true);
        }
        $filter->clearIssues();
        $lineCounter++;
    }
    fclose($fileHandler);
}