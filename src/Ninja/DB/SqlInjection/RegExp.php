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

class RegExp
{
    private string $description;
    private string $regexp;

    public function __construct(string $regexp, string $description)
    {
        $this->regexp = $regexp;
        $this->description = $description;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function setDescription(string $description): void
    {
        $this->description = $description;
    }

    public function getRegexp(): string
    {
        return $this->regexp;
    }

    public function setRegexp(string $regexp): void
    {
        $this->regexp = $regexp;
    }

}