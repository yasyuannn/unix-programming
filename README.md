# unix-programming

1. Implement a ‘lsof’-like program
 
2. Monitor File and Directory Activities of Dynamically Linked Programs
 - 透過 Library Injection 和 API Hijacking 實作一個 Sandbox 環境。
 - 利用 LD_PRELOAD 來製作 hook，以達到監控某些 glibc function 的目的。
 
3. Extend the Mini Lib C to Handle Signals
 - 寫一個小型的 C library，包括實做 entry point 以及 system call 的包裝。

4. Simple Instruction Level Debugger
 - 利用 ptrace 來實作一個類似 gdb 的 debugger。
