if (!exists("rule")) rule=0
filename="rule".rule.".data"

TI='`head -1 '.filename.'.title`'
set title @TI

plot filename using 1:2 with lines
pause 1
reread
