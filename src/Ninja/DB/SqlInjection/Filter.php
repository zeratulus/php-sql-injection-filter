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

use PhpMyAdmin\SqlParser\Lexer;
use PhpMyAdmin\SqlParser\Parser;
use PhpMyAdmin\SqlParser\TokensList;

class Filter
{
    private string $input = "";
    private array $messages = [];

    private array $sqlBoolOperators = [
        "=", "<=", ">=", "<>", "!=", "or", "and", "not", "if", "else"
    ];

    private array $sqlWhereOperators = [
        "like", "where", "between", "group", "null", "%"
    ];

    private array $sqlCommands = [
        "cast", "exec", "declare", "execute", "truncate", "grant", "privileges", "concat"
    ];

    private array $sqlOtherStrings = [
        "select", "drop", "from",  "exists", "update", "delete", "insert",  "http", "https", "sql",
        "mysql", "()", "information_schema", "timestamp", "version", "join", "having", "__TIME__",
        "signed", "alter", "union", "create", "shutdown", "some", "all", "any",
        "contains", "containsall", "containskey", "inner", "outer", "left", "right", "sleep"
    ];

    private array $unwantedStrings = [
        "username", "admin",
    ];

    private array $stringsToCheck = [

    ];

    private array $regExpsToCheck = [];

    private array $issuesFound = [
        'strings' => [],
        'regexps' => [],
        'errors' => [],
        'isValidSql' => false,
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

    private function checkWithParser(string $sql): void
    {
        $parser = new Parser($sql);
        if (empty($parser->errors)) {
            $this->issuesFound['isValidSql'] = true;
        } else {
            foreach ($parser->errors as $error) {
                $this->issuesFound['errors'][] = $error->getMessage();
            }
            $this->issuesFound['isValidSql'] = false;
        }
    }

    private function getLexems(): TokensList
    {
        $lexer = new Lexer($this->input);
        return $lexer->list;
    }

    public function init(): Filter
    {
        $this->stringsToCheck = array_merge($this->sqlBoolOperators, $this->sqlWhereOperators, $this->sqlCommands, $this->sqlOtherStrings, $this->unwantedStrings);

        $this->regExpsToCheck[] = new RegExp("/(?<!\/)\/\*((?:(?!\*\/).|\s)*)\*\//", "Found /* and */ injection");
        $this->regExpsToCheck[] = new RegExp("/--.*$/", "-- sql comment injection");
        $this->regExpsToCheck[] = new RegExp("(;+|\"+|'+)", "One or more ; and at least one \" or '");
        $this->regExpsToCheck[] = new RegExp('/"{2,}/', 'Two or more "');
        $this->regExpsToCheck[] = new RegExp('/\d\s*[=><!]\s*\d/', "anydigit (=/>=/<=/!=/<>) anydigit injection");
        $this->regExpsToCheck[] = new RegExp('/["][\w\s]+["]\s*=\s*["][\w\s]+["]|[\d\.]+\s*=\s*[\d\.]+/i', "something = something injection - 1");
        $this->regExpsToCheck[] = new RegExp('/["][\w\s]+["]\s*=\s*["][\w\s]+["]/i', "something = something injection - 2");
        $this->regExpsToCheck[] = new RegExp("/['][\w\s]+[']\s*=\s*['][\w\s]+[']/i", "something = something injection - 3");
        $this->regExpsToCheck[] = new RegExp("/[\w\s]+[']\s*=\s*['][\w\s]+/i", "something = something injection - 4");
        $this->regExpsToCheck[] = new RegExp('/[\w\s]+["]\s*=\s*["][\w\s]+/i', "something = something injection - 5");
        $this->regExpsToCheck[] = new RegExp('/[\w\s]+\s*=\s*[\w\s]+/i', "something = something injection - 6");
        $this->regExpsToCheck[] = new RegExp("/(#.*)$/", "# at end of sql injection");
        $this->regExpsToCheck[] = new RegExp('/%{2,}+/', "Two or more % signs");
        $this->regExpsToCheck[] = new RegExp("/([;\'\"\\=]+.*(admin.*))|((admin.*).*[;\'\"\\=]+)/", "admin (and variations like administrator) and one of [; ' \" =] before or after admin injection");
        $this->regExpsToCheck[] = new RegExp("/([;\'\"\\=]+.*(root))|((root).*[;\'\"\\=]+)/", "root and one of [; ' \" =] before or after root injection");
        $this->regExpsToCheck[] = new RegExp("/%+[0-7]+[0-9|A-F]+/", "ASCII Hex injection");

        // Union-based injection
        $this->regExpsToCheck[] = new RegExp("/\s*UNION\s+ALL\s+SELECT/i", "Union-based injection");
        $this->regExpsToCheck[] = new RegExp("/\s*UNION\s+DISTINCT\s+SELECT/i", "Union-based injection");
        $this->regExpsToCheck[] = new RegExp("/\s*UNION\s+SELECT/i", "Union-based injection");

        // Blind injection (time-based)
        $this->regExpsToCheck[] = new RegExp("/\s*SLEEP\(\d+\)/i", "Time-based blind injection");
        $this->regExpsToCheck[] = new RegExp("/\s*BENCHMARK\(\d+,\s*MD5\(\d+\)\)/i", "Time-based blind injection");
        $this->regExpsToCheck[] = new RegExp("/\s*PG_SLEEP\(\d+\)/i", "Time-based blind injection");

        // Blind injection (boolean-based)
        $this->regExpsToCheck[] = new RegExp("/\s*OR\s+'\d+'='\d'/i", "Boolean-based blind injection");
        $this->regExpsToCheck[] = new RegExp("/\s*OR\s+\d+=\d/i", "Boolean-based blind injection");
        $this->regExpsToCheck[] = new RegExp("/\s*AND\s+\d+=\d/i", "Boolean-based blind injection");
        $this->regExpsToCheck[] = new RegExp("/\s*AND\s+'\d+'='\d'/i", "Boolean-based blind injection");

        // Error-based injection
        $this->regExpsToCheck[] = new RegExp("/\s*CAST\(.*\s+AS\s+\w+\)/i", "Error-based injection");
        $this->regExpsToCheck[] = new RegExp("/\s*CONVERT\(.*\s+USING\s+\w+\)/i", "Error-based injection");

        // Comment injection
        $this->regExpsToCheck[] = new RegExp("/--/i", "Comment injection");
        $this->regExpsToCheck[] = new RegExp("/#/i", "Comment injection");
        $this->regExpsToCheck[] = new RegExp("/\/\*[\s\S]*\*\//i", "Comment injection");

        // Stacked queries
        $this->regExpsToCheck[] = new RegExp("/;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|GRANT|REVOKE|SHUTDOWN)/i", "Stacked queries injection");

        // Hex encoding
        $this->regExpsToCheck[] = new RegExp("/0x[a-f0-9]+/i", "Hex encoding injection");

        // URL encoding
        $this->regExpsToCheck[] = new RegExp("/%20(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|GRANT|REVOKE|SHUTDOWN)/i", "URL encoding injection");

        // Special characters
        $this->regExpsToCheck[] = new RegExp("/['\"]+(OR|AND)\s+['\"]+\d+['\"]+=\s*['\"]+\d+['\"]+/i", "Special characters injection");

        // File manipulation
        $this->regExpsToCheck[] = new RegExp("/\s*LOAD_FILE\(\s*['\"].*['\"]\s*\)/i", "File manipulation injection");
        $this->regExpsToCheck[] = new RegExp("/\s*INTO\s+DUMPFILE/i", "File manipulation injection");

        // Information schema
        $this->regExpsToCheck[] = new RegExp("/\s*INFORMATION_SCHEMA\.\w+/i", "Information schema injection");

        // Functions
        $this->regExpsToCheck[] = new RegExp("/\s*(MD5|SHA1|CONCAT|SUBSTR|MID|LEFT|RIGHT|ASCII|CHAR|ORD)\(/i", "Functions injection");

        // Variables
        $this->regExpsToCheck[] = new RegExp("/@\w+/i", "Variables injection");

        // Meta-SQL injection
        $this->regExpsToCheck[] = new RegExp("/\s*EXEC\s+\w+/i", "Meta-SQL injection");
        $this->regExpsToCheck[] = new RegExp("/\s*xp_cmdshell/i", "Meta-SQL injection");

        return $this;
    }

    public function check(string $input): bool
    {
        $this->input = $input;
        $strLower = strtolower($input);

        $this->checkStrings($strLower);
        $this->checkRegExps($input);
        if (!empty($this->issuesFound['strings'])) {
            $this->checkWithParser($input);
        }

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

        $this->messages = [];

        $this->input = "";
    }

    public function isIssues(): bool
    {
        return !empty($this->issuesFound['errors']) || !empty($this->issuesFound['strings']) || !empty($this->issuesFound['regexps']);
    }

    public function isSqlInjection(): bool
    {
        $result = false;

        //Check
        if (!empty($this->issuesFound['isValidSql'])) {
            $this->messages[] = 'Valid SQL query.';
            $result = true;
        }

        //Check
        if (!empty($this->issuesFound['regexps'])) {
            $validationMessages = array_keys($this->issuesFound['regexps']);
            foreach ($validationMessages as $message) {
                if (str_contains(strtolower($message), 'injection')) {
                    $this->messages[] = $message;
                    $result = true;
                }
            }
        }

        if (!empty($this->issuesFound['strings'])) {
            $strings = array_keys($this->issuesFound['strings']);

            $isNull = in_array('null', $strings);
            $isSelectFull = (in_array('select', $strings) && in_array('from', $strings));
            $isUpdateFull = (in_array('update', $strings) && in_array('set', $strings));
            $isInsertFull = (in_array('insert', $strings) && in_array('into', $strings));
            $isDeleteFull = (in_array('delete', $strings) && in_array('from', $strings));
            $isExec = (in_array('exec', $strings) || in_array('execute', $strings));
            $isJoinFull = (in_array('join', $strings) &&
                (in_array('inner', $strings) || in_array('outer', $strings) || in_array('left', $strings) || in_array('right', $strings))
            );

            $keywordsTotal = 0;
            foreach ($this->getLexems()->tokens as $token) {
                if (!empty($token->keyword)) {
                    $keywordsTotal++;
                }
            }

            //Check
            if ($isSelectFull || $isUpdateFull || $isInsertFull || $isDeleteFull || $isJoinFull || $isExec || $isNull && $keywordsTotal) {
                if ($isSelectFull) {
                    $this->messages[] = 'Contains SELECT FROM sequence!';
                }

                if ($isUpdateFull) {
                    $this->messages[] = 'Contains UPDATE SET sequence!';
                }

                if ($isInsertFull) {
                    $this->messages[] = 'Contains INSERT INTO sequence!';
                }

                if ($isDeleteFull) {
                    $this->messages[] = 'Contains DELETE FROM sequence!';
                }

                if ($isJoinFull) {
                    $this->messages[] = 'Contains <INNER/OUTER/LEFT/RIGHT> JOIN sequence!';
                }

                if ($isExec) {
                    $this->messages[] = 'Contains EXEC!';
                }

                if ($isNull) {
                    $this->messages[] = 'Contains NULL!';
                }

                $result = true;
            }

            //Check
            $sqlBoolOperators = 0;
            $sqlWhereOperators = 0;

            foreach ($this->sqlBoolOperators as $value) {
                if (in_array($value, array_keys($this->issuesFound['strings']))) {
                    $sqlBoolOperators++;
                }
            }

            foreach ($this->sqlWhereOperators as $value) {
                if (in_array($value, array_keys($this->issuesFound['strings']))) {
                    $sqlWhereOperators++;
                }
            }

            if ($sqlWhereOperators > 1 || $sqlBoolOperators >= 2 && $keywordsTotal > 5 && $this->isContainStrDelimeters()) {
                $this->messages[] = 'Contains part of WHERE clause or bool logic!';
                $result = true;
            }
        }

        return $result;
    }

    private function isContainStrDelimeters(): bool
    {
        $delimeters = ['"', "'"];
        foreach ($delimeters as $delimeter) {
            if (str_contains($this->input, $delimeter)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return array
     */
    public function getMessages(): array
    {
        return $this->messages;
    }

}