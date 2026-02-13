pushd .
Get-ChildItem -Path . -Directory -Recurse |
    foreach {
        cd $_.FullName
        &clang-format -i *.cpp
        &clang-format -i *.c
        &clang-format -i *.h
    }
popd