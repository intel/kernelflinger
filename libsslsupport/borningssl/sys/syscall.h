/*
function needed for compiling borningssl on Android O
*/
#pragma once
long syscall(long __number, ...){return 0;};
