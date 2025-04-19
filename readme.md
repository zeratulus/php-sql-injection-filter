# php-sql-injection-filter

### Currently under development

## Installation
>composer require zeratulus/php-sql-injection-filter

Usage example:
```php 
$result = (new Ninja\DB\SqlInjection())->init()->check($myStringToCheck);
```

Or more default OOP way:
```php
$filter = new Ninja\DB\SqlInjection();
$filter->init();
$result = $filter->check($myStringToCheck);
```

Some comments:
>Also you can use after call check(); method results of isSqlInjection();

> To clean results of check use clearIssues();

> Good example of usage is here: /tests/index.php 

This solution was implemented to detect possible SQL injection at user input.

In search of solution for this purpose I google some info... but there were nothing for PHP.

Big thanks to Stuart Millar for Java implementation.
Basic code were taken from here: https://github.com/stu17682/sql-injection-filter

Implemented with ChatGPT and Gemini.

With best regards Serhii Herenko
