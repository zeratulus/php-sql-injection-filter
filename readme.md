# php-sql-injection-filter

This solution was implemented to detect possible SQL injection at user input.

In search of solution for this purpose I google some info... but there were nothing for PHP.

Big thanks to Stuart Millar for Java implementation.

Basic code were taken from here: https://github.com/stu17682/sql-injection-filter

With best regards Serhii Herenko

Usage example:
> (new Ninja\DB\SqlInjection())->init()->check($myStringToCheck);

Or more default OOP way:
> $filter = new Ninja\DB\SqlInjection();
> 
> $filter->init();
> 
> $filter->check($myStringToCheck);