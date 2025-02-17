<?php
/*
 * Copyright Serhii Herenko (c) 2024.
 * PS. Basic code were taken from here: https://github.com/stu17682/sql-injection-filter
 *
 * Big thanks to Stuart Millar for Java implementation
 *
 * With best regards Serhii Herenko
 */

namespace Ninja\DB\SqlInjection;

class Filter
{
    private array $stringsToCheck = [
        "select", "drop", "from", "exec", "exists", "update", "delete", "insert", "cast", "http", "https", "sql",
        "null", "like", "mysql", "()", "information_schema", "timestamp", "version", "join", "declare", "having",
        "signed", "alter", "group", "union", "where", "create", "shutdown", "grant", "privileges", "truncate",
        "between", "contains", "containsall", "containskey", "=", "<=", ">=",
    ];

    private array $regExpsToCheck = [];

    private array $issuesFound = [
        'strings' => [],
        'regexps' => []
    ];

    /**
     * Method that checks on all possible regular expressions in string
     */
    private function checkRegExps(string $value): void
    {
        /**
         * @var $regexp RegExp
         */
        foreach ($this->regExpsToCheck as $regexp) {
            if (preg_match($regexp->getRegexp(), $value)) {
                !isset($this->issuesFound['regexps'][$regexp->getDescription()]) ?
                    $this->issuesFound['regexps'][$regexp->getDescription()] = 1 :
                        $this->issuesFound['regexps'][$regexp->getDescription()]++;
            }
        }
    }

    /**
     * Method that checks on all possible SQL commands in search string
     */
    private function checkStrings(string $value): void
    {
        foreach ($this->stringsToCheck as $string) {
            if (str_contains($value, $string)) {
                !isset($this->issuesFound['strings'][$string]) ?
                    $this->issuesFound['strings'][$string] = 1 :
                        $this->issuesFound['strings'][$string]++;
            }
        }
    }

    public function init(): Filter
    {
        $this->regExpsToCheck[] = new RegExp("/(?<!\/)\/\*((?:(?!\*\/).|\s)*)\*\//", "Found /* and */");
        $this->regExpsToCheck[] = new RegExp("/--.*$/", "-- sql comment");
        $this->regExpsToCheck[] = new RegExp("(;+|\"+|'+)", "One or more ; and at least one \" or '");
        $this->regExpsToCheck[] = new RegExp('/"{2,}/', 'Two or more "');
        $this->regExpsToCheck[] = new RegExp('/\d\s*[=><!]\s*\d/', "anydigit (=/>=/<=/!=/<>) anydigit");
        $this->regExpsToCheck[] = new RegExp('/(\\s\\s)+/', "two or more white spaces in a row");
        $this->regExpsToCheck[] = new RegExp("/(#.*)$/", "# at end of sql");
        $this->regExpsToCheck[] = new RegExp('/%{2,}+/', "Two or more % signs");
        $this->regExpsToCheck[] = new RegExp("/([;\'\"\\=]+.*(admin.*))|((admin.*).*[;\'\"\\=]+)/", "admin (and variations like administrator) and one of [; ' \" =] before or after admin");
        $this->regExpsToCheck[] = new RegExp("/([;\'\"\\=]+.*(root))|((root).*[;\'\"\\=]+)/", "root and one of [; ' \" =] before or after root");
        $this->regExpsToCheck[] = new RegExp("/%+[0-7]+[0-9|A-F]+/", "ASCII Hex");

        return $this;
    }

    public function check(string $input): bool
    {
        $strToCheck = strtolower($input);

        $this->checkRegExps($strToCheck);
        $this->checkStrings($strToCheck);

        return !empty($this->issuesFound);
    }

    public function getIssues(): array
    {
        return $this->issuesFound;
    }

    public function clearIssues(): void
    {
        $this->issuesFound = [
            'strings' => [],
            'regexps' => []
        ];
    }

}