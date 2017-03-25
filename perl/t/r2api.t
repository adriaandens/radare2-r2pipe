use strict;
use warnings;

use Radare::r2api;
use Data::Printer;

my $r2api = Radare::r2api->new('/bin/ls');
p $r2api->info();
print $r2api->info()->{static};
$r2api->analyze();
p $r2api->getFunctions();
$r2api->seek('0x00412b60');
$r2api->disassembleFunction();
$r2api->disassembleFunction('0x00404030');
