# AFLPIN

AFLPIN enables the AFL fuzzer (http://lcamtuf.coredump.cx/afl/) to fuzz non-instrumented binaries using Intel's PIN. 

It does so by inserting the same type of branch detection and shared memory mappings that AFL adds to instrumented binaries.  
Unfortunately it does so at a large cost to performance of AFL, so expect slow exec times.

## Building

First download the current version on the PIN library from https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool

Then build AFLPIN tool's .so file for use with pin:

	$ PIN_ROOT=/path/to/pin/root/ make obj-intel64/aflpin.so
	$ PIN_ROOT=/path/to/pin/root/ make TARGET=ia32 obj-ia32/aflpin.so

Then a command (to be run as root), to enable pin to be run from userland:
echo 0 > /proc/sys/kernel/yama/ptrace_scope

## Usage

In order to use the AFLPIN with afl-fuzz I had to comment out a single sanity check because of how pin is invoked from AFL:

in afl-fuzz.c:5578 (afl-1.15b) there is a sanity check:

    if (!dumb_mode && !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {
     ...
    }

Comment this line out and rebuild afl-fuzz.

Then to invoke the pin tool with a target and afl-fuzz:

	$ AFL_NO_FORKSRV=1 afl-fuzz -m 500 -i .. -o .. -f .. -- /path/to/pin_app -t /path/to/obj-intel64|obj-ia32/aflpin.so -- TARGETAPP @@

### Notes

*  -m 500   is because pin will need a large chunk of memory and you very well might need to tune this for a given target
*  Change out obj-intel64/ for obj-ia32/ if the target is 32 vs 64 bit.


## Test programs

crash_test.c is a simple process that reads in a file (as per and argument) that has a simple memcpy() vulnerability. 
	I use this to verify that signals are transfered correctly from the target through pin to afl-fuzz

sleep_test.c is used to verify the branch checking in AFLPIN, you can invoke the pin tool without afl without modifying 
the arguments.  also there is a -debug flag you can pass to the pin binary that will print extra information inside AFLPIN.

If AFL reports that the test case resulted in a crash, check the pin.log file in your current working directory for pin specific errors.